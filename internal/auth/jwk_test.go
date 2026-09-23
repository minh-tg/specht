package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseECDSAPublicKeyAcceptsStandardCurves(t *testing.T) {
	curves := []struct {
		name  string
		curve elliptic.Curve
	}{
		{name: "P-256", curve: elliptic.P256()},
		{name: "P-384", curve: elliptic.P384()},
		{name: "P-521", curve: elliptic.P521()},
	}

	for _, tt := range curves {
		t.Run(tt.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(tt.curve, rand.Reader)
			require.NoError(t, err)

			publicKey, err := parseECDSAPublicKey(
				tt.name,
				base64.RawURLEncoding.EncodeToString(privateKey.X.Bytes()),
				base64.RawURLEncoding.EncodeToString(privateKey.Y.Bytes()),
			)
			require.NoError(t, err)
			assert.True(t, publicKey.Equal(&privateKey.PublicKey))

			message := sha256.Sum256([]byte("public key conversion"))
			r, s, err := ecdsa.Sign(rand.Reader, privateKey, message[:])
			require.NoError(t, err)
			assert.True(t, ecdsa.Verify(publicKey, message[:], r, s))
		})
	}
}

func TestParseECDSAPublicKeyRejectsInvalidCoordinates(t *testing.T) {
	tooLarge := base64.RawURLEncoding.EncodeToString(make([]byte, 33))
	tests := []struct {
		name string
		crv  string
		x    string
		y    string
	}{
		{name: "unsupported curve", crv: "P-224", x: "AA", y: "AA"},
		{name: "invalid x encoding", crv: "P-256", x: "!", y: "AA"},
		{name: "invalid y encoding", crv: "P-256", x: "AA", y: "!"},
		{name: "coordinate too large", crv: "P-256", x: tooLarge, y: "AA"},
		{name: "point not on curve", crv: "P-256", x: "AA", y: "AA"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := parseECDSAPublicKey(tt.crv, tt.x, tt.y)
			assert.Nil(t, key)
			assert.Error(t, err)
		})
	}
}

func TestOIDCIdentityFromIDTokenAcceptsES256JWKSKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	coordinateSize := (privateKey.Curve.Params().BitSize + 7) / 8
	coordinate := func(value *big.Int) string {
		encoded := make([]byte, coordinateSize)
		value.FillBytes(encoded)
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	jwks, err := json.Marshal(struct {
		Keys []jwksKey `json:"keys"`
	}{Keys: []jwksKey{{
		Kid: "es256-test-kid",
		Kty: "EC",
		Alg: "ES256",
		Use: "sig",
		Crv: "P-256",
		X:   coordinate(privateKey.X),
		Y:   coordinate(privateKey.Y),
	}}})
	require.NoError(t, err)

	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwks.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	defer issuer.Close()

	a, err := NewOIDCAuthenticator(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "secret",
		IssuerURL:    issuer.URL,
		RedirectURI:  "http://localhost:8080/callback",
	}, nil)
	require.NoError(t, err)

	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss":   issuer.URL,
		"aud":   "test-client",
		"sub":   "es256-user",
		"email": "es256@example.com",
		"iat":   now.Unix(),
		"exp":   now.Add(time.Hour).Unix(),
		"nonce": "state-bound-nonce",
	})
	token.Header["kid"] = "es256-test-kid"
	rawToken, err := token.SignedString(privateKey)
	require.NoError(t, err)

	identity, err := a.identityFromIDToken(context.Background(), rawToken, "state-bound-nonce")
	require.NoError(t, err)
	require.NotNil(t, identity)
	assert.Equal(t, "es256-user", identity.UserID)
	assert.Equal(t, "es256@example.com", identity.Email)
}
