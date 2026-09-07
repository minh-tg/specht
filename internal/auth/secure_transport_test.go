package auth

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSecureTransport_ForwardedHeaderIgnoredWithoutMiddleware pins the L2
// default-deny rule: secureCookie must not mark a cookie Secure merely because
// the client sent X-Forwarded-Proto. Only the router's realIPMiddleware (which
// checks the trusted-proxy configuration) may convert that header into a
// security decision, by stamping the request context.
func TestSecureTransport_ForwardedHeaderIgnoredWithoutMiddleware(t *testing.T) {
	req := httptest.NewRequest("GET", "/callback", nil)
	req.Header.Set("X-Forwarded-Proto", "https")

	assert.False(t, SecureTransport(req),
		"a direct request must never trust a client-supplied X-Forwarded-Proto")
	assert.False(t, secureCookie(req, &http.Cookie{Name: "c"}).Secure)
}

// TestSecureTransport_MiddlewareVerdictHonored verifies that a context stamped
// by realIPMiddleware (trusted proxy present, X-Forwarded-Proto https) is
// honored by secureCookie.
func TestSecureTransport_MiddlewareVerdictHonored(t *testing.T) {
	req := httptest.NewRequest("GET", "/callback", nil)
	req = req.WithContext(ContextWithSecureTransport(req.Context(), true))

	assert.True(t, SecureTransport(req))
	assert.True(t, secureCookie(req, &http.Cookie{Name: "c"}).Secure)
}

// TestSecureTransport_NegativeVerdictBeatsTLSlessRequest: an explicit
// not-secure verdict (peer trusted but no TLS evidence) must not fall through
// to header sniffing.
func TestSecureTransport_NegativeVerdictHonored(t *testing.T) {
	req := httptest.NewRequest("GET", "/callback", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req = req.WithContext(ContextWithSecureTransport(req.Context(), false))

	assert.False(t, SecureTransport(req))
	assert.False(t, secureCookie(req, &http.Cookie{Name: "c"}).Secure)
}

// TestSecureTransport_DirectTLSFallback keeps the pre-middleware behavior for
// embedders that terminate TLS in-process and call handlers directly: direct
// TLS alone marks the transport secure.
func TestSecureTransport_DirectTLSFallback(t *testing.T) {
	req := httptest.NewRequest("GET", "/callback", nil)
	req.TLS = &tls.ConnectionState{}

	assert.True(t, SecureTransport(req))
	assert.True(t, secureCookie(req, &http.Cookie{Name: "c"}).Secure)
}
