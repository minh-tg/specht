package server

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/auth"
)

// testOIDC builds an OIDC authenticator for router-level SSO tests. The
// issuer is a loopback URL (permitted over plain HTTP) and is never actually
// contacted: the login handler only builds the provider's authorize URL.
func testOIDC(t *testing.T) *auth.OIDCAuthenticator {
	t.Helper()
	oidc, err := auth.NewOIDCAuthenticator(auth.OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "secret",
		IssuerURL:    "http://127.0.0.1",
		RedirectURI:  "http://127.0.0.1/api/v1/auth/sso/callback",
	}, nil)
	require.NoError(t, err)
	return oidc
}

// ssoStateCookie extracts the sso_state cookie from a recorder's response.
func ssoStateCookie(t *testing.T, w *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, c := range w.Result().Cookies() {
		if c.Name == "sso_state" {
			return c
		}
	}
	require.FailNow(t, "response carried no sso_state cookie")
	return nil
}

func TestRealIP_UntrustedPeerHeadersIgnored(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"x-forwarded-for", "X-Forwarded-For"},
		{"x-real-ip", "X-Real-IP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.RemoteAddr
			})
			mw := realIPMiddleware(nil) // default: no trusted proxies
			req := httptest.NewRequest("GET", "/", nil)
			req.RemoteAddr = "203.0.113.10:4444" // direct internet client
			req.Header.Set(tc.header, "198.51.100.9")
			mw(next).ServeHTTP(httptest.NewRecorder(), req)

			assert.Equal(t, "203.0.113.10:4444", got,
				"a spoofed %s from an untrusted peer must not rewrite RemoteAddr", tc.header)
		})
	}
}

func TestRealIP_TrustedProxyHeadersHonored(t *testing.T) {
	mw := realIPMiddleware([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("192.168.0.0/16"),
	})

	t.Run("x-forwarded-for uses leftmost entry", func(t *testing.T) {
		var got string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.RemoteAddr
		})
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.5:8080"
		req.Header.Set("X-Forwarded-For", "198.51.100.7, 10.0.0.5")
		mw(next).ServeHTTP(httptest.NewRecorder(), req)

		assert.Equal(t, "198.51.100.7", got)
	})

	t.Run("x-real-ip", func(t *testing.T) {
		var got string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.RemoteAddr
		})
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "192.168.1.20:8080"
		req.Header.Set("X-Real-IP", "198.51.100.8")
		mw(next).ServeHTTP(httptest.NewRecorder(), req)

		assert.Equal(t, "198.51.100.8", got)
	})

	t.Run("peer outside configured ranges still denied", func(t *testing.T) {
		var got string
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = r.RemoteAddr
		})
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "172.16.0.1:1234"
		req.Header.Set("X-Forwarded-For", "6.6.6.6")
		mw(next).ServeHTTP(httptest.NewRecorder(), req)

		assert.Equal(t, "172.16.0.1:1234", got)
	})
}

func TestSSOLogin_SecureCookieRequiresTrustedProxy(t *testing.T) {
	t.Run("spoofed X-Forwarded-Proto from direct client is ignored", func(t *testing.T) {
		h := ssoLoginHandler(testOIDC(t))
		req := httptest.NewRequest("GET", "/api/v1/auth/sso/login", nil)
		req.RemoteAddr = "198.51.100.7:5678" // direct internet client
		req.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()

		h(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.False(t, ssoStateCookie(t, w).Secure,
			"an untrusted client must not be able to force a Secure sso_state cookie")
	})

	t.Run("X-Forwarded-Proto honored from configured trusted proxy", func(t *testing.T) {
		router := NewRouter(RouterConfig{
			Usecases:       &mockUsecases{},
			JWTAuth:        testJWTAuth,
			OIDC:           testOIDC(t),
			OIDCEnabled:    true,
			TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		})
		req := httptest.NewRequest("GET", "/api/v1/auth/sso/login", nil)
		req.RemoteAddr = "10.1.2.3:443"
		req.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusFound, w.Code)
		assert.True(t, ssoStateCookie(t, w).Secure,
			"a TLS-terminating proxy inside the trusted ranges must set a Secure cookie")
	})

	t.Run("direct plain HTTP stays non-secure even behind trusted proxy", func(t *testing.T) {
		// A trusted proxy that did not terminate TLS (no X-Forwarded-Proto)
		// must not yield a Secure cookie the browser would then refuse to send.
		h := ssoLoginHandler(testOIDC(t))
		req := httptest.NewRequest("GET", "/api/v1/auth/sso/login", nil)
		req.RemoteAddr = "198.51.100.7:5678"
		w := httptest.NewRecorder()

		h(w, req)

		assert.False(t, ssoStateCookie(t, w).Secure)
	})
}
