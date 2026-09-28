//go:build e2e

package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The SSO round-trip against the loopback IdP and the trusted-proxy
// transport verdict.

// noRedirectClient surfaces every redirect instead of following it, so each
// leg of the SSO dance can be asserted and re-issued with explicit cookies.
func noRedirectClient() *http.Client {
	return &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
}

// ssoLoginLeg performs GET /auth/sso/login and returns the IdP redirect,
// the issued state cookie, and the response headers.
func ssoLoginLeg(t *testing.T, forwardedProto string) (string, []*http.Cookie, http.Header) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, baseURL+"/api/v1/auth/sso/login", nil)
	require.NoError(t, err)
	if forwardedProto != "" {
		req.Header.Set("X-Forwarded-Proto", forwardedProto)
	}
	resp, err := noRedirectClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	return resp.Header.Get("Location"), resp.Cookies(), resp.Header
}

// ssoExchange drives login → IdP authorize → callback without a cookie jar:
// the state cookie travels as an explicit header (a jar would refuse a
// Secure cookie over plain http, exactly as a browser behind TLS
// termination would hand it back over the https leg).
func ssoExchange(t *testing.T, forwardedProto string) (int, string, http.Header) {
	t.Helper()
	authorize, cookies, _ := ssoLoginLeg(t, forwardedProto)

	var stateCookie *http.Cookie
	for _, c := range cookies {
		if c.Name == "sso_state" {
			stateCookie = c
		}
	}
	require.NotNil(t, stateCookie, "the flow binds state to a cookie")

	// The IdP redirects back to the registered callback with code+state.
	req, err := http.NewRequest(http.MethodGet, authorize, nil)
	require.NoError(t, err)
	resp, err := noRedirectClient().Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	back := resp.Header.Get("Location")

	// The callback: cookie + forwarded headers as the browser (behind the
	// proxy) would send them.
	cb, err := url.Parse(back)
	require.NoError(t, err)
	cbReq, err := http.NewRequest(http.MethodGet, cb.String(), nil)
	require.NoError(t, err)
	cbReq.AddCookie(stateCookie)
	if forwardedProto != "" {
		cbReq.Header.Set("X-Forwarded-Proto", forwardedProto)
	}
	cbResp, err := noRedirectClient().Do(cbReq)
	require.NoError(t, err)
	defer cbResp.Body.Close()

	var body strings.Builder
	_, _ = body.WriteString(cbResp.Header.Get("Location"))
	return cbResp.StatusCode, cbResp.Header.Get("Location"), cbResp.Header
}

// ssoToken pulls the session token out of a successful callback redirect.
func ssoToken(t *testing.T, status int, location string) string {
	t.Helper()
	require.Equal(t, http.StatusFound, status)
	require.True(t, strings.HasPrefix(location, "/#sso_token="),
		"the token travels in the URL fragment: %s", location)
	token, err := url.PathUnescape(strings.TrimPrefix(location, "/#sso_token="))
	require.NoError(t, err)
	require.NotEmpty(t, token)
	return token
}

// TestE2E_SSOLoginAndProvisioning closes the SSO API-side journey: redirect
// with state+nonce, provision on first login, deny outside the allowlist,
// and never change an existing user's role.
func TestE2E_SSOLoginAndProvisioning(t *testing.T) {
	t.Run("first login provisions an allowlisted admin-group user", func(t *testing.T) {
		fakes.idp.setEmail("e2e-sso-full@example.com")
		status, location, _ := ssoExchange(t, "")
		token := ssoToken(t, status, location)

		me := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", token, nil, http.StatusOK)
		require.Equal(t, "e2e-sso-full@example.com", me.Email)
		require.Equal(t, "admin", me.Role,
			"the platform-team admin group provisions a global admin")
	})

	t.Run("the allowlist denies foreign domains and empty emails", func(t *testing.T) {
		defer fakes.idp.setEmail(e2eSSOEmail)

		fakes.idp.setEmail("intruder@evil-tenant.io")
		status, location, _ := ssoExchange(t, "")
		require.Equal(t, http.StatusForbidden, status,
			"a domain outside SSO_ALLOWED_DOMAINS is refused: %s", location)

		fakes.idp.setEmail("")
		status, location, _ = ssoExchange(t, "")
		require.Equal(t, http.StatusForbidden, status,
			"an empty email is refused: %s", location)
	})

	t.Run("sso never changes an existing user's role", func(t *testing.T) {
		email := "e2e-sso-role@example.com"
		status, _ := doJSON(t, http.MethodPost, "/api/v1/auth/register", "",
			map[string]string{"email": email, "password": adminPass})
		require.Equal(t, http.StatusCreated, status)
		passwordToken := login(t, email, adminPass)
		passwordMe := request[profileEnvelope](t, http.MethodGet, "/api/v1/me",
			passwordToken, nil, http.StatusOK)
		require.NotEqual(t, "admin", passwordMe.Role,
			"registration never mints admins — the assertion cannot be vacuous")

		fakes.idp.setEmail(email)
		status, location, _ := ssoExchange(t, "")
		token := ssoToken(t, status, location)
		ssoMe := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", token, nil, http.StatusOK)
		require.Equal(t, passwordMe.ID, ssoMe.ID, "same account, two transports")
		require.Equal(t, passwordMe.Role, ssoMe.Role,
			"group membership never promotes or demotes an existing user")
	})
}

// TestE2E_TrustedProxySecureTransport covers the transport verdict: the
// (proxy-aware) drives cookie Secure attributes and HSTS, and the secure
// journey completes end to end.
func TestE2E_TrustedProxySecureTransport(t *testing.T) {
	t.Run("plain http is never marked secure", func(t *testing.T) {
		_, cookies, headers := ssoLoginLeg(t, "")
		var state *http.Cookie
		for _, c := range cookies {
			if c.Name == "sso_state" {
				state = c
			}
		}
		require.NotNil(t, state)
		require.False(t, state.Secure, "no TLS and no trusted verdict → plain cookie")
		require.Empty(t, headers.Get("Strict-Transport-Security"),
			"HSTS only rides on a verified secure transport")
	})

	t.Run("a trusted proxy's https verdict marks cookies secure", func(t *testing.T) {
		_, cookies, headers := ssoLoginLeg(t, "https")
		var state *http.Cookie
		for _, c := range cookies {
			if c.Name == "sso_state" {
				state = c
			}
		}
		require.NotNil(t, state)
		require.True(t, state.Secure,
			"X-Forwarded-Proto: https from the trusted hop marks the cookie")
		require.NotEmpty(t, headers.Get("Strict-Transport-Security"),
			"HSTS follows the same verdict")
	})

	t.Run("the secure journey completes end to end", func(t *testing.T) {
		fakes.idp.setEmail("e2e-sso-proxy@example.com")
		status, location, _ := ssoExchange(t, "https")
		token := ssoToken(t, status, location)
		me := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", token, nil, http.StatusOK)
		require.Equal(t, "e2e-sso-proxy@example.com", me.Email)
	})
}
