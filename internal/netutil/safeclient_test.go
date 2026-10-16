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
