package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// callbackAs sends the callback the way a browser or an API client would.
func callbackAs(a *OIDCAuthenticator, accept, query string, cookies []*http.Cookie, issuer func(context.Context, SSOClaims) (string, error)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/callback?"+query, nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	w := httptest.NewRecorder()
	a.CallbackHandler(issuer)(w, req)
	return w
}

const browserAccept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"

func TestCallback_SendsARefusedBrowserBackToSignIn(t *testing.T) {
	idp := newStrictIdP(t)
	a := idp.authFor(t)
	notProvisioned := func(context.Context, SSOClaims) (string, error) { return "", ErrSSONotProvisioned }
	invalidEmail := func(context.Context, SSOClaims) (string, error) { return "", ErrSSOInvalidEmail }

	t.Run("an account the server cannot let in keeps the page it was going to", func(t *testing.T) {
		login := startTestLogin(t, a, "/projects/demo?tab=findings")
		code := idp.authorize(t, login, "user-1")
		query := url.Values{"code": {code}, "state": {login.state}}.Encode()

		w := callbackAs(a, browserAccept, query, login.cookies, notProvisioned)

		require.Equal(t, http.StatusFound, w.Code)
		to, err := url.Parse(w.Header().Get("Location"))
		require.NoError(t, err)
		assert.Equal(t, "/login", to.Path)
		assert.Equal(t, "not_allowed", to.Query().Get("sso_error"))
		assert.Equal(t, "/projects/demo?tab=findings", to.Query().Get("redirect"))
		assert.Empty(t, to.Host, "stays on this server")
	})

	t.Run("an email the server cannot accept", func(t *testing.T) {
		login := startTestLogin(t, a, "/")
		code := idp.authorize(t, login, "user-1")
		query := url.Values{"code": {code}, "state": {login.state}}.Encode()

		w := callbackAs(a, browserAccept, query, login.cookies, invalidEmail)

		require.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "/login?sso_error=bad_email", w.Header().Get("Location"))
	})

	t.Run("a provider that denies access reads as denied, not a missing code", func(t *testing.T) {
		login := startTestLogin(t, a, "/")
		query := url.Values{"error": {"access_denied"}, "state": {login.state}}.Encode()

		w := callbackAs(a, browserAccept, query, login.cookies, notProvisioned)

		require.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "/login?sso_error=denied", w.Header().Get("Location"))
	})

	t.Run("a login this browser did not start reads as expired", func(t *testing.T) {
		w := callbackAs(a, browserAccept, "code=x&state=not-mine", nil, notProvisioned)

		require.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "/login?sso_error=expired", w.Header().Get("Location"))
	})

	t.Run("a denial with no valid state still proves nothing and reads as expired", func(t *testing.T) {
		w := callbackAs(a, browserAccept, "error=access_denied&state=not-mine", nil, notProvisioned)

		require.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "/login?sso_error=expired", w.Header().Get("Location"))
	})
}

// An API client that does not ask for a page keeps the status codes the API documents.
func TestCallback_KeepsStatusCodesForOtherClients(t *testing.T) {
	idp := newStrictIdP(t)
	a := idp.authFor(t)
	notProvisioned := func(context.Context, SSOClaims) (string, error) { return "", ErrSSONotProvisioned }

	login := startTestLogin(t, a, "/")
	code := idp.authorize(t, login, "user-1")
	query := url.Values{"code": {code}, "state": {login.state}}.Encode()
	w := callbackAs(a, "application/json", query, login.cookies, notProvisioned)
	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "sso account not provisioned")

	denied := startTestLogin(t, a, "/")
	w = callbackAs(a, "", url.Values{"error": {"access_denied"}, "state": {denied.state}}.Encode(), denied.cookies, notProvisioned)
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "refused the sign-in")

	w = callbackAs(a, "", "code=x&state=not-mine", nil, notProvisioned)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
