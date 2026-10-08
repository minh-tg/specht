package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewRouter_SSOWithNonJWTAuth_NoPanic guards against a regression where
// enabling OIDC with a JWTAuth that is not a *auth.JWTAuthenticator panicked
// on an unchecked type assertion inside the SSO callback's token issuer.
func TestNewRouter_SSOWithNonJWTAuth_NoPanic(t *testing.T) {
	// Minimal fake provider: the token endpoint returns an access token with
	// no id_token. Enable compatibility to exercise the later token-issuer
	// failure path this test is intended to cover.
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/token":
			w.Header().Set("Content-Type", "application/json")
			if _, err := fmt.Fprint(w, `{"access_token":"acc-test","token_type":"Bearer"}`); err != nil {
				t.Errorf("write token response: %v", err)
			}
		case "/userinfo":
			w.Header().Set("Content-Type", "application/json")
			if _, err := fmt.Fprint(w, `{"sub":"oidc-user-1","email":"oidc@example.com"}`); err != nil {
				t.Errorf("write userinfo response: %v", err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()

	oidc, err := auth.NewOIDCAuthenticator(auth.OIDCConfig{
		ClientID:          "test-client",
		ClientSecret:      "secret",
		IssuerURL:         provider.URL,
		RedirectURI:       "http://localhost:8080/api/v1/auth/sso/callback",
		AllowUserInfoOnly: true,
	}, nil)
	require.NoError(t, err)

	apiKeyAuth := auth.NewAPIKeyAuthenticator(func(ctx context.Context, keyHash string) (string, string, []string, time.Time, error) {
		return "", "", nil, time.Time{}, nil
	})

	router := NewRouter(RouterConfig{
		Usecases:    &mockUsecases{},
		JWTAuth:     apiKeyAuth, // not a *auth.JWTAuthenticator
		OIDC:        oidc,
		OIDCEnabled: true,
	})

	// Drive the callback through a real code exchange so the token-issuer
	// closure runs. The misconfigured JWTAuth must surface as the callback's
	// clean 500 ("token issuance failed") rather than a recovered panic.
	state := "test-state.test-nonce"
	req := httptest.NewRequest("GET", "/api/v1/auth/sso/callback?code=test-code&state="+state, nil)
	req.AddCookie(&http.Cookie{Name: "sso_state", Value: state})
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "token issuance failed")
}
