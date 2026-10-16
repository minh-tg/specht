package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
)

// testLogin is one SSO login started through StartLogin: what the
// authorization URL carried and the cookies the browser was given.
type testLogin struct {
	url       string
	state     string
	nonce     string
	challenge string
	cookies   []*http.Cookie
}

// startTestLogin starts a login for a browser with no earlier cookies.
func startTestLogin(t *testing.T, a *OIDCAuthenticator, returnPath string) testLogin {
	t.Helper()
	return startTestLoginWith(t, a, returnPath)
}

// startTestLoginWith starts a login for a browser that already holds cookies.
func startTestLoginWith(t *testing.T, a *OIDCAuthenticator, returnPath string, held ...*http.Cookie) testLogin {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/sso/login", nil)
	for _, c := range held {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	loginURL, err := a.StartLogin(rec, req, returnPath)
	require.NoError(t, err)
	q := mustParseQuery(t, loginURL)
	return testLogin{
		url:       loginURL,
		state:     q.Get("state"),
		nonce:     q.Get("nonce"),
		challenge: q.Get("code_challenge"),
		cookies:   rec.Result().Cookies(),
	}
}

// callbackRequest is the request the identity provider's redirect makes the
// browser send: the code and state in the query, the login's cookies attached.
func (l testLogin) callbackRequest(code string) *http.Request {
	return l.callbackRequestWith(code, l.cookies...)
}

// callbackRequestWith is callbackRequest with a chosen cookie jar.
func (l testLogin) callbackRequestWith(code string, cookies ...*http.Cookie) *http.Request {
	req := httptest.NewRequest(http.MethodGet,
		"/api/v1/auth/sso/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(l.state), nil)
	for _, c := range cookies {
		if c.MaxAge >= 0 {
			req.AddCookie(c)
		}
	}
	return req
}

// loginSecret reads the per-login secret out of a login's own cookie.
func loginSecret(t *testing.T, a *OIDCAuthenticator, l testLogin) string {
	t.Helper()
	for _, c := range l.cookies {
		if c.Name == ssoStateCookieName(l.state) {
			login, err := a.openLogin(l.state, c.Value)
			require.NoError(t, err)
			return login.secret
		}
	}
	require.FailNow(t, "login set no state cookie")
	return ""
}

// browserJar models the cookies one browser keeps between requests.
type browserJar map[string]*http.Cookie

// apply stores the cookies a response set and drops the ones it deleted.
func (j browserJar) apply(cookies []*http.Cookie) {
	for _, c := range cookies {
		if c.MaxAge < 0 {
			delete(j, c.Name)
			continue
		}
		j[c.Name] = c
	}
}

func (j browserJar) list() []*http.Cookie {
	out := make([]*http.Cookie, 0, len(j))
	for _, c := range j {
		out = append(out, c)
	}
	return out
}
