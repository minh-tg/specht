package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOIDC_Authenticate_NonOIDCToken(t *testing.T) {
	a := NewOIDCAuthenticator(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "secret",
		IssuerURL:    "https://example.com",
		RedirectURI:  "http://localhost:8080/api/v1/auth/sso/callback",
	}, nil)

	// Tokens that don't start with "oidc:" should fall through (ErrNotApplicable).
	ident, err := a.Authenticate(context.Background(), "some-other-token")
	assert.Nil(t, ident)
	assert.ErrorIs(t, err, ErrNotApplicable)
}

func TestOIDC_LoginURL(t *testing.T) {
	a := NewOIDCAuthenticator(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "secret",
		IssuerURL:    "https://example.com",
		RedirectURI:  "http://localhost:8080/callback",
	}, nil)

	u := a.LoginURL("csrf-state")
	assert.Contains(t, u, "https://example.com/oauth/authorize")
	assert.Contains(t, u, "client_id=test-client")
	assert.Contains(t, u, "redirect_uri=http")
	assert.Contains(t, u, "response_type=code")
	assert.Contains(t, u, "scope=openid+email+profile")
	assert.Contains(t, u, "state=csrf-state")
}

func TestOIDC_CallbackHandler_MissingCode(t *testing.T) {
	a := NewOIDCAuthenticator(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "secret",
		IssuerURL:    "https://example.com",
		RedirectURI:  "http://localhost:8080/callback",
	}, nil)

	h := a.CallbackHandler(func(userID, email string) (string, error) {
		return "token", nil
	})
	req := httptest.NewRequest("GET", "/api/v1/auth/sso/callback", nil)
	w := httptest.NewRecorder()
	h(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDC_CallbackHandler_MissingState(t *testing.T) {
	a := NewOIDCAuthenticator(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "secret",
		IssuerURL:    "https://example.com",
		RedirectURI:  "http://localhost:8080/callback",
	}, nil)

	h := a.CallbackHandler(func(userID, email string) (string, error) {
		return "token", nil
	})
	req := httptest.NewRequest("GET", "/callback?code=test-code", nil)
	w := httptest.NewRecorder()
	h(w, req)

	// No state cookie was set, so the callback must be refused.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDC_CallbackHandler_StateMismatch(t *testing.T) {
	a := NewOIDCAuthenticator(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "secret",
		IssuerURL:    "https://example.com",
		RedirectURI:  "http://localhost:8080/callback",
	}, nil)

	h := a.CallbackHandler(func(userID, email string) (string, error) {
		return "token", nil
	})
	req := httptest.NewRequest("GET", "/callback?code=test-code&state=attacker-state", nil)
	req.AddCookie(&http.Cookie{Name: "sso_state", Value: "real-state"})
	w := httptest.NewRecorder()
	h(w, req)

	// A state that does not match the cookie must be refused.
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
