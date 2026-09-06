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
	secret []byte
}

// NewJWTAuthenticator builds a JWT authenticator with the given HMAC secret.
func NewJWTAuthenticator(secret string) (*JWTAuthenticator, error) {
	if secret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}
	if secret == "dev-only-change-me" {
		return nil, fmt.Errorf("JWT_SECRET must not be the default value")
	}
	return &JWTAuthenticator{secret: []byte(secret)}, nil
}

func (a *JWTAuthenticator) CreateToken(userID, email, role string) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   tokenIssuer,
		"aud":   tokenAudience,
		"sub":   userID,
		"email": email,
		"role":  role,
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
		"sub":  userID,
		"type": "refresh",
		"iat":  now.Unix(),
		"exp":  now.Add(7 * 24 * time.Hour).Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return tok.SignedString(a.secret)
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
	if jti, _ := claims["jti"].(string); jti == "" {
		return nil, ErrInvalidCredential
	}
	sub, _ := claims.GetSubject()
	email, _ := claims["email"].(string)
	role, _ := claims["role"].(string)
	return &Identity{UserID: sub, Email: email, Role: role}, nil
}
