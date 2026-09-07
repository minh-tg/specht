package auth

import (
	"context"
	"fmt"
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

func TestOIDC_CallbackHandler_DeliversTokenInFragment(t *testing.T) {
	// Minimal fake provider: the token endpoint returns an access token with
	// no id_token, so identity extraction falls back to the userinfo endpoint.
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"access_token":"acc-test","token_type":"Bearer"}`)
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"sub":"oidc-user-1","email":"oidc@example.com"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	a := NewOIDCAuthenticator(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "secret",
		IssuerURL:    provider.URL,
		RedirectURI:  "http://localhost:8080/callback",
	}, nil)

	const issuedToken = "test-session-token"
	h := a.CallbackHandler(func(userID, email string) (string, error) {
		assert.Equal(t, "oidc-user-1", userID)
		assert.Equal(t, "oidc@example.com", email)
		return issuedToken, nil
	})

	state := "csrf-state"
	req := httptest.NewRequest("GET", "/callback?code=test-code&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "sso_state", Value: state})
	w := httptest.NewRecorder()
	h(w, req)

	// The session token must be delivered to the SPA as a URL fragment (which
	// is never sent to the server or leaked via Referer), not as an httpOnly
	// cookie that nothing in the stack ever reads.
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "/#sso_token="+issuedToken, w.Header().Get("Location"))
	for _, c := range w.Result().Cookies() {
		assert.NotEqual(t, "token", c.Name, "callback must not set a session cookie")
	}
}

func TestOIDC_Authenticate_RejectsOIDCBearer(t *testing.T) {
	a := NewOIDCAuthenticator(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "secret",
		IssuerURL:    "https://example.com",
		RedirectURI:  "http://localhost:8080/callback",
	}, nil)

	// The OIDC authenticator is only wired to the SSO login/callback flow; it
	// is never part of the bearer-auth chain. Treating "oidc:<code>" as a
	// bearer credential would put a one-time code into Authorization headers
	// and logs, so it must fall through like any other unrecognized token.
	ident, err := a.Authenticate(context.Background(), "oidc:anything")
	assert.Nil(t, ident)
	assert.ErrorIs(t, err, ErrNotApplicable)
	assert.NotErrorIs(t, err, ErrInvalidCredential)
}
