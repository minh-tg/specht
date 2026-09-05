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

func TestOIDC_CallbackHandler_TokenExchangeSuccess(t *testing.T) {
	var capturedUserID, capturedEmail string
	issuer := func(userID, email string) (string, error) {
		capturedUserID = userID
		capturedEmail = email
		return "session-token", nil
	}

	// Set up a mock OAuth2 provider.
	mockProvider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id_token":"eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEyMyIsImVtYWlsIjoidGVzdEBleGFtcGxlLmNvbSIsIm5hbWUiOiJUZXN0IFVzZXIifQ.signature","access_token":"access-123"}`))
	}))
	defer mockProvider.Close()

	a := NewOIDCAuthenticator(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "secret",
		IssuerURL:    mockProvider.URL,
		RedirectURI:  "http://localhost:8080/callback",
	}, nil)

	h := a.CallbackHandler(issuer)

	// Simulate the redirect with a code.
	req := httptest.NewRequest("GET", "/callback?code=test-code", nil)
	w := httptest.NewRecorder()
	h(w, req)

	// Should redirect (302) with the session token.
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "token=session-token")
	assert.Equal(t, "Test User", capturedUserID)
	assert.Equal(t, "test@example.com", capturedEmail)
}

func TestIdentity_RoleConstants(t *testing.T) {
	assert.Equal(t, "admin", RoleAdmin)
	assert.Equal(t, "editor", RoleEditor)
	assert.Equal(t, "viewer", RoleViewer)
}
