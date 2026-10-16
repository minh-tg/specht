package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

// resolvedRemoteAddr runs the real-IP middleware for a request from peer with
// the given header lines (repeated names become separate header lines) and
// returns the RemoteAddr a downstream handler sees.
func resolvedRemoteAddr(t *testing.T, trusted []string, peer string, headers [][2]string) string {
	t.Helper()
	var prefixes []netip.Prefix
	for _, p := range trusted {
		prefixes = append(prefixes, netip.MustParsePrefix(p))
	}
	var got string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { got = r.RemoteAddr })
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = peer
	for _, h := range headers {
		req.Header.Add(h[0], h[1])
	}
	realIPMiddleware(prefixes)(next).ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestRealIP_ResolvesTheRightmostUntrustedForwardedHop(t *testing.T) {
	trusted := []string{"10.0.0.0/8", "192.168.0.0/16", "fd00::/8"}
	const peer = "10.0.0.5:8080"
	xff := func(v ...string) [][2]string {
		var out [][2]string
		for _, s := range v {
			out = append(out, [2]string{"X-Forwarded-For", s})
		}
		return out
	}
	cases := []struct {
		name    string
		peer    string
		headers [][2]string
		want    string
	}{
		{"single line, one hop", peer, xff("198.51.100.7"), "198.51.100.7"},
		{"single line, client-supplied leading entries", peer, xff("203.0.113.66, 198.51.100.7"), "198.51.100.7"},
		{"single line, trusted hops on the right", peer, xff("203.0.113.66, 198.51.100.7, 192.168.1.5, 10.2.2.2"), "198.51.100.7"},
		{"two lines: the proxy's own line is last", peer, xff("203.0.113.66", "198.51.100.7"), "198.51.100.7"},
		{"two lines: client chooses nothing with a spoofed first line", peer, xff("1.1.1.1, 2.2.2.2", "198.51.100.7"), "198.51.100.7"},
		{"three lines with trusted hops on the last", peer, xff("1.1.1.1", "198.51.100.7", "192.168.3.3"), "198.51.100.7"},
		{"lines joined with spaces around entries", peer, xff(" 1.1.1.1 ", " 198.51.100.7 "), "198.51.100.7"},
		{"empty list elements are ignored", peer, xff("1.1.1.1", "198.51.100.7,"), "198.51.100.7"},
		{"IPv6 client", peer, xff("2001:db8::7"), "2001:db8::7"},
		{"IPv6 client behind an IPv6 trusted hop", "[fd00::1]:443", xff("203.0.113.66", "2001:db8::7", "fd00::2"), "2001:db8::7"},
		{"IPv4-mapped IPv6 entry reads as the IPv4 address", peer, xff("::ffff:198.51.100.7"), "198.51.100.7"},
		{"IPv4-mapped trusted hop is skipped", peer, xff("198.51.100.7, ::ffff:10.1.1.1"), "198.51.100.7"},
		{"malformed rightmost entry is not trusted and nothing to its left is used", peer, xff("198.51.100.7,not-an-ip"), peer},
		{"malformed entry behind a trusted hop", peer, xff("198.51.100.7, junk, 10.9.9.9"), peer},
		{"malformed entry to the left of the first untrusted hop is never reached", peer, xff("junk, 198.51.100.7"), "198.51.100.7"},
		{"bracketed IPv6 is malformed", peer, xff("[2001:db8::7]"), peer},
		{"zoned IPv6 is malformed", peer, xff("fe80::1%eth0"), peer},
		{"every hop trusted leaves the peer", peer, xff("10.1.1.1, 192.168.0.9"), peer},
		{"X-Real-IP only", peer, [][2]string{{"X-Real-IP", "198.51.100.8"}}, "198.51.100.8"},
		{"X-Real-IP with spaces and IPv6", peer, [][2]string{{"X-Real-IP", " 2001:db8::8 "}}, "2001:db8::8"},
		{"malformed X-Real-IP is ignored", peer, [][2]string{{"X-Real-IP", "nope"}}, peer},
		{"trusted X-Real-IP is ignored", peer, [][2]string{{"X-Real-IP", "10.4.4.4"}}, peer},
		{
			"both present: a usable X-Forwarded-For wins", peer,
			append(xff("198.51.100.7"), [2]string{"X-Real-IP", "198.51.100.8"}), "198.51.100.7",
		},
		{
			"both present: X-Real-IP covers an X-Forwarded-For with no usable hop", peer,
			append(xff("10.1.1.1"), [2]string{"X-Real-IP", "198.51.100.8"}), "198.51.100.8",
		},
		{
			"both present: X-Real-IP covers a malformed X-Forwarded-For", peer,
			append(xff("junk"), [2]string{"X-Real-IP", "198.51.100.8"}), "198.51.100.8",
		},
		{"no forwarding headers", peer, nil, peer},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, resolvedRemoteAddr(t, trusted, tc.peer, tc.headers))
		})
	}
}

func TestRealIP_UntrustedPeerNeverHasItsForwardedLinesRead(t *testing.T) {
	headers := [][2]string{
		{"X-Forwarded-For", "6.6.6.6"},
		{"X-Forwarded-For", "7.7.7.7"},
		{"X-Real-IP", "8.8.8.8"},
	}
	assert.Equal(t, "203.0.113.10:4444",
		resolvedRemoteAddr(t, []string{"10.0.0.0/8"}, "203.0.113.10:4444", headers))
	assert.Equal(t, "203.0.113.10:4444", resolvedRemoteAddr(t, nil, "203.0.113.10:4444", headers))
}

// A proxy that adds its own X-Forwarded-For line (HAProxy "option forwardfor")
// leaves the client's line first. The login tier must count the client under
// the address the proxy saw, not under one the client picked.
func TestRouter_LoginTierCountsTheProxyAppendedAddressNotTheClientLine(t *testing.T) {
	var evaluated atomic.Int64
	router := NewRouter(RouterConfig{
		Usecases: &mockUsecases{loginFn: func(context.Context, string, string) (*usecase.AuthResponse, error) {
			evaluated.Add(1)
			return nil, errors.New("invalid email or password")
		}},
		JWTAuth:        testJWTAuth,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
	})
	var limited int
	for i := range 50 {
		req := httptest.NewRequest("POST", "/api/v1/auth/login",
			strings.NewReader(fmt.Sprintf(`{"email":"user%d@example.com","password":"guess"}`, i)))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "10.0.0.5:4000"
		req.Header.Add("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i)) // the client's own line, rotating
		req.Header.Add("X-Forwarded-For", "198.51.100.6")                 // the proxy's line: the real client
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	require.Positive(t, limited, "one real client must hit the login bucket however its own line rotates")
	assert.LessOrEqual(t, evaluated.Load(), int64(defaultLoginBurst+1))
}
