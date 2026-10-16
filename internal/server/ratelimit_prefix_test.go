package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientHost_GroupsIPv6ByPrefix(t *testing.T) {
	cases := []struct{ remote, want string }{
		{"192.0.2.7:443", "192.0.2.7"},
		{"192.0.2.7", "192.0.2.7"},
		{"[2001:db8:1:2:aaaa:bbbb:cccc:dddd]:443", "2001:db8:1:2::/64"},
		{"[2001:db8:1:2::1]:443", "2001:db8:1:2::/64"},
		{"[2001:db8:1:3::1]:443", "2001:db8:1:3::/64"},
		{"2001:db8:1:2:ffff:ffff:ffff:ffff", "2001:db8:1:2::/64"},
		{"[fe80::1%eth0]:443", "fe80::/64"},
		{"[::ffff:192.0.2.7]:443", "192.0.2.7"},
		{"[::ffff:c000:207]:443", "192.0.2.7"},
		{"[::1]:443", "::/64"},
		{"not-an-address:1", "not-an-address"},
	}
	for _, tc := range cases {
		t.Run(tc.remote, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			assert.Equal(t, tc.want, clientHost(r))
		})
	}
}

func TestRateLimiter_IPv6ClientsInOnePrefixShareABucket(t *testing.T) {
	l := NewRateLimiter(1, 3)
	h := l.Middleware(false)(okHandler())
	send := func(remote string) int {
		req := httptest.NewRequest("GET", "/api/v1/projects", nil)
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code
	}
	for i := range 3 {
		require.Equal(t, http.StatusOK, send(fmt.Sprintf("[2001:db8:5:6::%x]:1", i+1)))
	}
	assert.Equal(t, http.StatusTooManyRequests, send("[2001:db8:5:6::ffff]:1"), "a fourth address in the /64 is out of budget")
	assert.Equal(t, http.StatusOK, send("[2001:db8:5:7::1]:1"), "the next /64 has its own budget")
	assert.Equal(t, 2, l.BucketCount())
}

func TestRouter_LoginTierCountsAnIPv6PrefixOnce(t *testing.T) {
	router := NewRouter(RouterConfig{Usecases: &mockUsecases{}, JWTAuth: testJWTAuth})
	limited := 0
	for i := range 40 {
		// A new email each time keeps the per-account delay out of the way.
		body := fmt.Sprintf(`{"email":"user%d@example.com","password":"guess"}`, i)
		req := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = fmt.Sprintf("[2001:db8:9::%x]:40000", i+1)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		if w.Code == http.StatusTooManyRequests {
			limited++
		}
	}
	assert.Equal(t, 40-defaultLoginBurst, limited, "rotating through a /64 spends one login budget, not one per address")
}
