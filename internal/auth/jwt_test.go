package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const jwtBindingTestSecret = "test-secret-for-jwt-binding-tests-0123456789"

// The bound-claim values self-issued tokens must carry. They mirror the
// tokenIssuer/tokenAudience constants in jwt.go; spelled out here so the
// tests pin the wire contract, not the implementation.
const (
	wantIssuer   = "specht"
	wantAudience = "specht-api"
)

// validBoundClaims returns a claim set that a correctly-bound access token
// must carry.
func validBoundClaims() jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{
		"iss":   wantIssuer,
		"aud":   wantAudience,
		"sub":   "user-1",
		"email": "user@example.com",
		"role":  RoleViewer,
		"jti":   uuid.NewString(),
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
	}
}

// signRaw signs claims with the authenticator's secret.
func signRaw(t *testing.T, a *JWTAuthenticator, claims jwt.MapClaims) string {
	t.Helper()
	raw, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.secret)
	require.NoError(t, err)
	return raw
}

// parseClaims decodes a token's claims using the authenticator's secret.
func parseClaims(t *testing.T, a *JWTAuthenticator, raw string) jwt.MapClaims {
	t.Helper()
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, assert.AnError
		}
		return a.secret, nil
	})
	require.NoError(t, err)
	claims, ok := tok.Claims.(jwt.MapClaims)
	require.True(t, ok, "claims should decode as a MapClaims")
	return claims
}

func TestJWT_CreateTokenIncludesBoundClaims(t *testing.T) {
	a, err := NewJWTAuthenticator(jwtBindingTestSecret)
	require.NoError(t, err)

	raw, err := a.CreateToken("user-1", "user@example.com", RoleViewer)
	require.NoError(t, err)

	claims := parseClaims(t, a, raw)
	assert.Equal(t, wantIssuer, claims["iss"], "access token must carry the issuer claim")

	aud, err := claims.GetAudience()
	require.NoError(t, err)
	assert.Contains(t, aud, wantAudience, "access token must carry the API audience claim")

	jti, _ := claims["jti"].(string)
	assert.NotEmpty(t, jti, "access token must carry a unique jti claim")

	exp, err := claims.GetExpirationTime()
	require.NoError(t, err)
	require.NotNil(t, exp, "access token must carry an exp claim")
	assert.True(t, exp.After(time.Now()), "minted access token must not already be expired")
}

func TestJWT_Authenticate_AcceptsMintedToken(t *testing.T) {
	a, err := NewJWTAuthenticator(jwtBindingTestSecret)
	require.NoError(t, err)

	raw, err := a.CreateToken("user-1", "user@example.com", RoleEditor)
	require.NoError(t, err)

	ident, err := a.Authenticate(context.Background(), raw)
	require.NoError(t, err)
	assert.Equal(t, "user-1", ident.UserID)
	assert.Equal(t, "user@example.com", ident.Email)
	assert.Equal(t, RoleEditor, ident.Role)
}

func TestJWT_Authenticate_RejectsMissingOrWrongBoundClaims(t *testing.T) {
	a, err := NewJWTAuthenticator(jwtBindingTestSecret)
	require.NoError(t, err)

	now := time.Now()
	tests := []struct {
		name   string
		mutate func(c jwt.MapClaims)
	}{
		{"missing exp", func(c jwt.MapClaims) { delete(c, "exp") }},
		{"expired", func(c jwt.MapClaims) { c["exp"] = now.Add(-time.Hour).Unix() }},
		{"missing issuer", func(c jwt.MapClaims) { delete(c, "iss") }},
		{"wrong issuer", func(c jwt.MapClaims) { c["iss"] = "someone-else" }},
		{"missing audience", func(c jwt.MapClaims) { delete(c, "aud") }},
		{"wrong audience", func(c jwt.MapClaims) { c["aud"] = "some-other-api" }},
		{"missing jti", func(c jwt.MapClaims) { delete(c, "jti") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims := validBoundClaims()
			tt.mutate(claims)
			raw := signRaw(t, a, claims)

			ident, err := a.Authenticate(context.Background(), raw)
			assert.Nil(t, ident, "authenticator must not return an identity for a %s token", tt.name)
			assert.ErrorIs(t, err, ErrInvalidCredential, "%s token must be an invalid credential", tt.name)
			assert.NotErrorIs(t, err, ErrNotApplicable, "%s token is signed with our key and must not fall through", tt.name)
		})
	}
}

func TestJWT_Authenticate_RejectsRefreshTokenAsAccessToken(t *testing.T) {
	a, err := NewJWTAuthenticator(jwtBindingTestSecret)
	require.NoError(t, err)

	raw, err := a.CreateRefreshToken("user-1")
	require.NoError(t, err)

	ident, err := a.Authenticate(context.Background(), raw)
	assert.Nil(t, ident)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}

func TestJWT_Authenticate_MalformedFallsThrough(t *testing.T) {
	a, err := NewJWTAuthenticator(jwtBindingTestSecret)
	require.NoError(t, err)

	ident, err := a.Authenticate(context.Background(), "not-a-jwt")
	assert.Nil(t, ident)
	assert.ErrorIs(t, err, ErrNotApplicable)
}

func TestJWT_Authenticate_RejectsWrongSignature(t *testing.T) {
	a, err := NewJWTAuthenticator(jwtBindingTestSecret)
	require.NoError(t, err)

	other, err := NewJWTAuthenticator("a-different-secret-for-other-keys-0123456789")
	require.NoError(t, err)
	raw := signRaw(t, other, validBoundClaims())

	ident, err := a.Authenticate(context.Background(), raw)
	assert.Nil(t, ident)
	assert.ErrorIs(t, err, ErrInvalidCredential)
}
