//go:build e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
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
// the issued state cookies, and the response headers.
func ssoLoginLeg(t *testing.T, forwardedProto string, returnPath ...string) (string, []*http.Cookie, http.Header) {
	t.Helper()
	loginURL := baseURL + "/api/v1/auth/sso/login"
	if len(returnPath) > 0 {
		query := url.Values{"redirect": []string{returnPath[0]}}
		loginURL += "?" + query.Encode()
	}
	req, err := http.NewRequest(http.MethodGet, loginURL, nil)
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

// ssoStateCookie picks the per-login state cookie (sso_state_<hash of state>)
// out of a response's cookies.
func ssoStateCookie(cookies []*http.Cookie) *http.Cookie {
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, "sso_state_") {
			return c
		}
	}
	return nil
}

// ssoExchange drives login → IdP authorize → callback without a cookie jar:
// the state cookies travel as explicit headers (a jar would refuse a Secure
// cookie over plain http, exactly as a browser behind TLS termination would
// hand them back over the https leg). It returns the callback's status and
// location, and the login cookies the browser holds for the exchange.
func ssoExchange(t *testing.T, forwardedProto string, returnPath ...string) (int, string, []*http.Cookie) {
	t.Helper()
	authorize, cookies, _ := ssoLoginLeg(t, forwardedProto, returnPath...)

	require.NotNil(t, ssoStateCookie(cookies), "the flow binds state to a cookie")

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
	for _, cookie := range cookies {
		cbReq.AddCookie(cookie)
	}
	if forwardedProto != "" {
		cbReq.Header.Set("X-Forwarded-Proto", forwardedProto)
	}
	cbResp, err := noRedirectClient().Do(cbReq)
	require.NoError(t, err)
	defer cbResp.Body.Close()

	return cbResp.StatusCode, cbResp.Header.Get("Location"), cookies
}

// ssoToken exchanges the code of a successful callback redirect, from the
// browser that started the login, and returns the session token.
func ssoToken(t *testing.T, status int, location string, cookies []*http.Cookie) string {
	t.Helper()
	st, body, _ := exchangeCode(t, ssoCodeFrom(t, status, location), cookies...)
	require.Equal(t, http.StatusOK, st, "sso exchange must succeed: %s", string(body))
	type exchangeResp struct {
		Token string `json:"token"`
	}
	var resp exchangeResp
	require.NoError(t, json.Unmarshal(body, &resp))
	require.NotEmpty(t, resp.Token)
	return resp.Token
}

// ssoCodeFrom reads the exchange code out of a successful callback redirect.
func ssoCodeFrom(t *testing.T, status int, location string) string {
	t.Helper()
	require.Equal(t, http.StatusFound, status)
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(parsed.Fragment, "sso_code="),
		"the token travels in the URL fragment: %s", location)
	code, err := url.PathUnescape(strings.TrimPrefix(parsed.Fragment, "sso_code="))
	require.NoError(t, err)
	require.NotEmpty(t, code)
	return code
}

// exchangeCode posts an SSO exchange code from a browser that holds cookies.
// It returns the status, the body and the cookies the response set.
func exchangeCode(t *testing.T, code string, cookies ...*http.Cookie) (int, []byte, []*http.Cookie) {
	t.Helper()
	raw, err := json.Marshal(map[string]string{"code": code})
	require.NoError(t, err)
	req, err := http.NewRequest(http.MethodPost, baseURL+"/api/v1/auth/sso/exchange", bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	resp, err := noRedirectClient().Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body, resp.Cookies()
}

// TestE2E_SSOLoginAndProvisioning closes the SSO API-side journey: redirect
// with state+nonce, provision on first login, deny outside the allowlist,
// and never change an existing user's role.
func TestE2E_SSOLoginAndProvisioning(t *testing.T) {
	t.Run("first login provisions an allowlisted admin-group user and preserves the deep link", func(t *testing.T) {
		fakes.idp.setEmail("e2e-sso-full@example.com")
		status, location, cookies := ssoExchange(t, "", "/projects/demo?tab=members")
		token := ssoToken(t, status, location, cookies)

		returned, err := url.Parse(location)
		require.NoError(t, err)
		require.Equal(t, "/projects/demo", returned.Path)
		require.Equal(t, "tab=members", returned.RawQuery)

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

	t.Run("an email the provider does not vouch for is refused", func(t *testing.T) {
		defer fakes.idp.setEmailVerified(true)
		defer fakes.idp.setEmail(e2eSSOEmail)

		fakes.idp.setEmail("e2e-sso-unverified@example.com")
		fakes.idp.setEmailVerified(false)
		status, location, _ := ssoExchange(t, "")
		require.Equal(t, http.StatusForbidden, status,
			"an unverified email cannot provision or link: %s", location)
	})

	t.Run("a second subject with a linked account's email cannot take it over", func(t *testing.T) {
		defer fakes.idp.setSubject("")
		defer fakes.idp.setEmail(e2eSSOEmail)

		fakes.idp.setEmail("e2e-sso-bound@example.com")
		status, location, cookies := ssoExchange(t, "")
		owner := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", ssoToken(t, status, location, cookies), nil, http.StatusOK)

		fakes.idp.setSubject("some-other-subject")
		status, location, cookies = ssoExchange(t, "")
		require.Equal(t, http.StatusForbidden, status,
			"the same email under a different subject is refused: %s", location)

		fakes.idp.setSubject("")
		status, location, cookies = ssoExchange(t, "")
		again := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", ssoToken(t, status, location, cookies), nil, http.StatusOK)
		require.Equal(t, owner.ID, again.ID, "the rightful subject still signs in")
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
		status, location, cookies := ssoExchange(t, "")
		token := ssoToken(t, status, location, cookies)
		ssoMe := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", token, nil, http.StatusOK)
		require.Equal(t, passwordMe.ID, ssoMe.ID, "same account, two transports")
		require.Equal(t, passwordMe.Role, ssoMe.Role,
			"group membership never promotes or demotes an existing user")

		status, _ = doJSON(t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": email, "password": adminPass})
		require.Equal(t, http.StatusUnauthorized, status,
			"linking through the provider retires the password that may have been set by someone else")
	})

	t.Run("only a verified sso login proves the address for ADMIN_EMAILS", func(t *testing.T) {
		defer fakes.idp.setEmail(e2eSSOEmail)
		proven := func(email string) bool {
			t.Helper()
			ctx := context.Background()
			conn, err := pgx.Connect(ctx, dsn)
			require.NoError(t, err)
			defer conn.Close(ctx)
			var out bool
			require.NoError(t, conn.QueryRow(ctx, "SELECT email_proven FROM users WHERE email = $1", email).Scan(&out))
			return out
		}

		registered := "e2e-sso-proof-registered@example.com"
		status, _ := doJSON(t, http.MethodPost, "/api/v1/auth/register", "",
			map[string]string{"email": registered, "password": adminPass})
		require.Equal(t, http.StatusCreated, status)
		require.False(t, proven(registered), "registering with a password proves nothing")

		fakes.idp.setEmail(registered)
		status, location, cookies := ssoExchange(t, "")
		ssoToken(t, status, location, cookies)
		require.True(t, proven(registered), "the provider vouched for the address when the account was linked")

		provisioned := "e2e-sso-proof-new@example.com"
		fakes.idp.setEmail(provisioned)
		status, location, cookies = ssoExchange(t, "")
		ssoToken(t, status, location, cookies)
		require.True(t, proven(provisioned), "a provisioned account arrives with a vouched address")
	})
}

// TestE2E_TrustedProxySecureTransport covers the transport verdict: the
// (proxy-aware) drives cookie Secure attributes and HSTS, and the secure
// journey completes end to end.
func TestE2E_TrustedProxySecureTransport(t *testing.T) {
	t.Run("plain http is never marked secure", func(t *testing.T) {
		_, cookies, headers := ssoLoginLeg(t, "")
		state := ssoStateCookie(cookies)
		require.NotNil(t, state)
		require.False(t, state.Secure, "no TLS and no trusted verdict → plain cookie")
		require.Empty(t, headers.Get("Strict-Transport-Security"),
			"HSTS only rides on a verified secure transport")
	})

	t.Run("a trusted proxy's https verdict marks cookies secure", func(t *testing.T) {
		_, cookies, headers := ssoLoginLeg(t, "https")
		state := ssoStateCookie(cookies)
		require.NotNil(t, state)
		require.True(t, state.Secure,
			"X-Forwarded-Proto: https from the trusted hop marks the cookie")
		require.NotEmpty(t, headers.Get("Strict-Transport-Security"),
			"HSTS follows the same verdict")
	})

	t.Run("the secure journey completes end to end", func(t *testing.T) {
		fakes.idp.setEmail("e2e-sso-proxy@example.com")
		status, location, cookies := ssoExchange(t, "https")
		token := ssoToken(t, status, location, cookies)
		me := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", token, nil, http.StatusOK)
		require.Equal(t, "e2e-sso-proxy@example.com", me.Email)
	})
}
