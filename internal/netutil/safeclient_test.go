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
