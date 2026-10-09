package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claim values bound onto every self-issued token. Authenticate rejects any
// token that does not carry exactly these, so a token minted elsewhere (or a
// bare signed payload with no exp) can never authenticate here.
const (
	tokenIssuer   = "specht"
	tokenAudience = "specht-api"
)

// JWTAuthenticator signs and verifies JWT access tokens.
type JWTAuthenticator struct {
	secret   []byte
	revoker  Revoker
	versions TokenVersionSource
}

// TokenVersionSource reports an account's current access-token generation.
// Access tokens minted for an older generation are rejected.
type TokenVersionSource interface {
	TokenVersion(ctx context.Context, userID string) (int32, error)
}

// WithTokenVersions enables the per-account generation check on every access
// token. Without it, Authenticate skips that check.
func (a *JWTAuthenticator) WithTokenVersions(src TokenVersionSource) *JWTAuthenticator {
	a.versions = src
	return a
}

// NewJWTAuthenticator builds a JWT authenticator with the given HMAC secret.
func NewJWTAuthenticator(secret string) (*JWTAuthenticator, error) {
	return NewJWTAuthenticatorWithRevoker(secret, NewMemoryRevoker())
}

// NewJWTAuthenticatorWithRevoker builds an authenticator using the supplied
// shared revocation store.
func NewJWTAuthenticatorWithRevoker(secret string, revoker Revoker) (*JWTAuthenticator, error) {
	if secret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}
	if secret == "dev-only-change-me" {
		return nil, fmt.Errorf("JWT_SECRET must not be the default value")
	}
	if len(secret) < 32 {
		return nil, fmt.Errorf("JWT_SECRET must be at least 32 bytes")
	}
	if revoker == nil {
		return nil, fmt.Errorf("revoker is required")
	}
	return &JWTAuthenticator{secret: []byte(secret), revoker: revoker}, nil
}

func (a *JWTAuthenticator) CreateToken(userID, email, role string, tokenVersion int32) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   tokenIssuer,
		"aud":   tokenAudience,
		"sub":   userID,
		"email": email,
		"role":  role,
		"tv":    tokenVersion,
		"jti":   uuid.NewString(),
		"iat":   now.Unix(),
		"exp":   now.Add(15 * time.Minute).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	return tok.SignedString(a.secret)
}

func (a *JWTAuthenticator) CreateRefreshToken(userID string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		// jti keeps every mint unique: the refresh-token store keys on the
		// SHA-256 of the whole token, so two mints for one user in the same
		// second would otherwise be byte-identical and collide on the unique
		// hash index (surfacing as a generic login/refresh failure).
		"jti":  uuid.NewString(),
		"sub":  userID,
		"type": "refresh",
		"iat":  now.Unix(),
		"exp":  now.Add(7 * 24 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(a.secret)
}

// RevokeToken verifies and revokes an access token by its JWT ID.
func (a *JWTAuthenticator) RevokeToken(token string) error {
	return a.RevokeTokenContext(context.Background(), token)
}

// RevokeTokenContext is the context-aware revocation path used by HTTP logout.
func (a *JWTAuthenticator) RevokeTokenContext(ctx context.Context, token string) error {
	tok, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return a.secret, nil
	}, jwt.WithIssuer(tokenIssuer), jwt.WithAudience(tokenAudience), jwt.WithExpirationRequired())
	if err != nil {
		return errors.Join(ErrInvalidCredential, err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return ErrInvalidCredential
	}
	jti, _ := claims["jti"].(string)
	exp, ok := claims["exp"].(float64)
	if jti == "" || !ok {
		return ErrInvalidCredential
	}
	if a.revoker == nil {
		return nil
	}
	return a.revoker.Revoke(ctx, jti, time.Unix(int64(exp), 0))
}

func (a *JWTAuthenticator) Authenticate(ctx context.Context, token string) (*Identity, error) {
	tok, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return a.secret, nil
	}, jwt.WithIssuer(tokenIssuer), jwt.WithAudience(tokenAudience), jwt.WithExpirationRequired())
	if err != nil {
		if errors.Is(err, jwt.ErrTokenMalformed) {
			return nil, ErrNotApplicable
		}
		return nil, errors.Join(ErrInvalidCredential, err)
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, ErrInvalidCredential
	}

	if tokenType, _ := claims["type"].(string); tokenType == "refresh" {
		return nil, ErrInvalidCredential
	}
	// Access tokens must carry a unique JWT ID so they can be individually
	// identified (and later revoked/audited). jwt v5 offers no
	// WithJTIRequired option, so require the claim explicitly.
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, ErrInvalidCredential
	}
	if a.revoker != nil {
		revoked, checkErr := a.revoker.IsRevoked(ctx, jti)
		if checkErr != nil {
			return nil, errors.Join(ErrInvalidCredential, checkErr)
		}
		if revoked {
			return nil, ErrInvalidCredential
		}
	}
	sub, _ := claims.GetSubject()
	if a.versions != nil {
		// Fail closed: a token whose generation cannot be confirmed against the
		// account is refused, so a lookup error or a missing claim never admits it.
		current, verErr := a.versions.TokenVersion(ctx, sub)
		if verErr != nil {
			return nil, errors.Join(ErrInvalidCredential, verErr)
		}
		if tv, ok := claims["tv"].(float64); !ok || int32(tv) != current {
			return nil, ErrInvalidCredential
		}
	}
	email, _ := claims["email"].(string)
	role, _ := claims["role"].(string)
	return &Identity{UserID: sub, Email: email, Role: role}, nil
}
