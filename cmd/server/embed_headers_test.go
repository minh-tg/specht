package main

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/server"
)

func spaWithProxy(t *testing.T) http.Handler {
	t.Helper()
	assets := fstest.MapFS{
		"dist/index.html":         {Data: []byte("<!doctype html><title>Specht</title>")},
		"dist/assets/app-a1b2.js": {Data: []byte("console.log('app')")},
	}
	router := server.NewRouter(server.RouterConfig{TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	return spaHandlerWithFS(router, assets, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
}

func spaGet(h http.Handler, path, remote, proto string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = remote
	if proto != "" {
		req.Header.Set("X-Forwarded-Proto", proto)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Text files carry an explicit charset, whether the shell is asked for by name
// or reached through a client-side route.
func TestSPAHandler_TextFilesDeclareUTF8(t *testing.T) {
	h := spaWithProxy(t)
	for path, want := range map[string]string{
		"/index.html":         "text/html; charset=utf-8",
		"/":                   "text/html; charset=utf-8",
		"/acme/findings":      "text/html; charset=utf-8",
		"/assets/app-a1b2.js": "text/javascript; charset=utf-8",
	} {
		rec := spaGet(h, path, "192.0.2.1:1234", "")
		// The file server redirects /index.html to ./; the header is set
		// before it decides, so it is the same on either answer.
		assert.Contains(t, []int{http.StatusOK, http.StatusMovedPermanently}, rec.Code, path)
		assert.Equal(t, want, rec.Header().Get("Content-Type"), path)
	}
}

// Behind a TLS-terminating proxy the shell and assets carry HSTS the way API
// responses do.
func TestSPAHandler_HSTSBehindATrustedTLSProxy(t *testing.T) {
	h := spaWithProxy(t)
	for _, path := range []string{"/", "/acme/findings", "/assets/app-a1b2.js", "/api/v1/health"} {
		rec := spaGet(h, path, "10.1.2.3:4444", "https")
		assert.NotEmpty(t, rec.Header().Get("Strict-Transport-Security"), "trusted proxy, https: %s", path)

		rec = spaGet(h, path, "10.1.2.3:4444", "http")
		assert.Empty(t, rec.Header().Get("Strict-Transport-Security"), "trusted proxy, http: %s", path)
	}
}

// A client that is not a trusted proxy cannot make the server send HSTS by
// claiming https.
func TestSPAHandler_NoHSTSFromAnUntrustedPeerClaimingHTTPS(t *testing.T) {
	h := spaWithProxy(t)
	for _, path := range []string{"/", "/assets/app-a1b2.js", "/api/v1/health"} {
		rec := spaGet(h, path, "203.0.113.9:4444", "https")
		assert.Empty(t, rec.Header().Get("Strict-Transport-Security"), path)
	}
}

// With no trusted proxies configured, forwarding headers are ignored on the
// file branch too.
func TestSPAHandler_NoTrustedProxiesIgnoresForwardedProto(t *testing.T) {
	assets := fstest.MapFS{"dist/index.html": {Data: []byte("<!doctype html>")}}
	h := spaHandlerWithFS(http.NotFoundHandler(), assets, nil)
	rec := spaGet(h, "/", "10.1.2.3:4444", "https")
	assert.Empty(t, rec.Header().Get("Strict-Transport-Security"))
}
