package netutil

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{
		"127.0.0.1",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"169.254.169.254", // Cloud metadata
		"::1",
		"fc00::1",
		"fe80::1",
		"2001:db8::1",  // Documentation
		"64:ff9b::1",   // NAT64
		"100.64.0.1",   // Carrier-grade NAT
		"198.18.0.1",   // Benchmarking
		"192.0.2.1",    // Documentation
		"198.51.100.1", // Documentation
		"203.0.113.1",  // Documentation
		"240.0.0.1",    // Reserved
		"0.0.0.0",      // Unspecified
		"0.1.2.3",      // "This network" 0.0.0.0/8, not only the unspecified address
		"0.255.255.255",
		"2002:a9fe:a9fe::1", // 6to4 embedding 169.254.169.254
		"2002:808:808::1",   // 6to4 embedding a public IPv4: still a relay path
		"::a9fe:a9fe",       // IPv4-compatible (::/96) embedding 169.254.169.254
		"::7f00:1",          // IPv4-compatible embedding 127.0.0.1
		"::2",
		"2001::1", // Teredo
		"2001:0:4136:e378:8000:63bf:3fff:fdd2",
		"fec0::1", // Site-local
		"feff::1", // Top of fec0::/10
		"100::1",  // Discard-only 100::/64
		"100::ffff:ffff:ffff:ffff",
		"2001:10::1",      // ORCHID
		"2001:1f::1",      // Top of 2001:10::/28
		"2001:20::1",      // ORCHIDv2
		"::ffff:10.0.0.1", // IPv4-mapped private
		"::ffff:0.1.2.3",  // IPv4-mapped 0.0.0.0/8
	}
	for _, ipStr := range blocked {
		t.Run(ipStr, func(t *testing.T) {
			assert.True(t, IsBlockedIP(net.ParseIP(ipStr)), "%s should be blocked", ipStr)
		})
	}

	public := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34",
		"2606:4700:4700::1111",
		"2001:4860:4860::8888", // 2001::/16 outside Teredo and ORCHID
		"2001:30::1",           // Just above 2001:20::/28
		"2003::1",              // Just above 6to4
		"2a00:1450:4001::200e",
		"100:0:0:1::1",   // Just outside 100::/64
		"fe7f::1",        // Below fec0::/10 and not link-local
		"1.0.0.1",        // Just above 0.0.0.0/8
		"::ffff:8.8.8.8", // IPv4-mapped public
	}
	for _, ipStr := range public {
		t.Run(ipStr, func(t *testing.T) {
			assert.False(t, IsBlockedIP(net.ParseIP(ipStr)), "%s should be allowed", ipStr)
		})
	}
}

// TestIsBlockedIP_TranslationAndSpecialRanges pins the ranges added after the
// first blocklist: SIIT (which embeds an IPv4 address like NAT64 does) and four
// special-purpose blocks. Each row names its first and last address, one
// address inside, and the nearest public address on either side, so removing a
// prefix or widening it past its edge fails here.
func TestIsBlockedIP_TranslationAndSpecialRanges(t *testing.T) {
	tests := []struct {
		name    string
		blocked []string
		below   string
		above   string
	}{
		{
			name:    "SIIT IPv4-translated ::ffff:0:0:0/96",
			blocked: []string{"::ffff:0:0:0", "::ffff:0:a9fe:a9fe", "::ffff:0:a00:1", "::ffff:0:ffff:ffff"},
			below:   "0:0:0:0:fffe:ffff:ffff:ffff",
			above:   "0:0:0:0:ffff:1:0:0",
		},
		{
			name:    "6to4 relay anycast 192.88.99.0/24",
			blocked: []string{"192.88.99.0", "192.88.99.1", "192.88.99.255", "::ffff:192.88.99.1"},
			below:   "192.88.98.255",
			above:   "192.88.100.0",
		},
		{
			name:    "benchmarking 2001:2::/48",
			blocked: []string{"2001:2::", "2001:2::1", "2001:2:0:ffff:ffff:ffff:ffff:ffff"},
			below:   "2001:1:ffff:ffff:ffff:ffff:ffff:ffff",
			above:   "2001:2:1::",
		},
		{
			name:    "documentation 3fff::/20",
			blocked: []string{"3fff::", "3fff::1", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"},
			below:   "3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
			above:   "3fff:1000::",
		},
		{
			name:    "SRv6 SIDs 5f00::/16",
			blocked: []string{"5f00::", "5f00::1", "5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
			below:   "5eff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
			above:   "5f01::",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, s := range tt.blocked {
				ip := net.ParseIP(s)
				require.NotNil(t, ip, s)
				assert.True(t, IsBlockedIP(ip), "%s should be blocked", s)
			}
			for _, s := range []string{tt.below, tt.above} {
				ip := net.ParseIP(s)
				require.NotNil(t, ip, s)
				assert.False(t, IsBlockedIP(ip), "%s is public and should be allowed", s)
			}
		})
	}
}

func TestIsLoopbackHost(t *testing.T) {
	assert.True(t, IsLoopbackHost("localhost"))
	assert.True(t, IsLoopbackHost("127.0.0.1"))
	assert.True(t, IsLoopbackHost("::1"))
	assert.False(t, IsLoopbackHost("example.com"))
	assert.False(t, IsLoopbackHost("169.254.169.254"))
	assert.False(t, IsLoopbackHost("10.0.0.1"))
}

func TestSafeHTTPClient_BlocksPrivateIP(t *testing.T) {
	client := NewSafeHTTPClient(2 * time.Second)

	// Attempt to connect to cloud metadata IP
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://169.254.169.254/latest/meta-data/", nil)
	require.NoError(t, err)

	_, err = client.Do(req)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing connection to non-public address")
}

func TestSafeHTTPClient_AllowsLoopbackWhenTargetIsLoopback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	client := SafeHTTPClientForURL(srv.URL, 2*time.Second)
	resp, err := client.Get(srv.URL)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
}

func TestSafeHTTPClient_RefusesRedirects(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/", http.StatusFound)
	}))
	defer srv.Close()

	client := SafeHTTPClientForURL(srv.URL, 2*time.Second)
	_, err := client.Get(srv.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redirects are not allowed")
}

func TestSafeDialContextAllowHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	require.NoError(t, err)

	dial := func(allowedHost, host string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		conn, err := SafeDialContextAllowHost(&net.Dialer{Timeout: 200 * time.Millisecond}, false, allowedHost)(ctx, "tcp", net.JoinHostPort(host, port))
		if conn != nil {
			_ = conn.Close()
		}
		return err
	}

	t.Run("the allowed loopback host connects", func(t *testing.T) {
		require.NoError(t, dial("127.0.0.1", "127.0.0.1"))
	})
	t.Run("the host match ignores case", func(t *testing.T) {
		require.NoError(t, dial("LOCALHOST", "localhost"))
	})
	t.Run("another host is refused although the exception is on", func(t *testing.T) {
		err := dial("10.0.0.5", "127.0.0.1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing connection to non-public address")
	})
	t.Run("a name that resolves to loopback is not the allowed host", func(t *testing.T) {
		err := dial("127.0.0.1", "localhost")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing connection to non-public address")
	})
	t.Run("the allowed private host passes the guard", func(t *testing.T) {
		// Nothing listens on 10.255.255.1, so the dial fails for lack of a
		// route or by timeout. It must not fail at the guard.
		if err := dial("10.255.255.1", "10.255.255.1"); err != nil {
			assert.NotContains(t, err.Error(), "refusing connection")
		}
	})
	t.Run("the same private host is refused without the exception", func(t *testing.T) {
		err := dial("", "10.255.255.1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing connection to non-public address")
	})
	t.Run("link-local passes the guard for the allowed host only", func(t *testing.T) {
		if err := dial("169.254.10.10", "169.254.10.10"); err != nil {
			assert.NotContains(t, err.Error(), "refusing connection")
		}
	})
	t.Run("a public-looking special range stays refused for the allowed host", func(t *testing.T) {
		err := dial("100.64.0.1", "100.64.0.1")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "refusing connection to non-public address")
	})
}
