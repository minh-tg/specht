package main

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/config"
)

func prefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var out []netip.Prefix
	for _, c := range cidrs {
		out = append(out, netip.MustParsePrefix(c))
	}
	return out
}

func TestCatchAllProxyWarning_NamesTheCatchAllRanges(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cidrs []string
		want  []string
	}{
		{"ipv4 catch-all", []string{"0.0.0.0/0"}, []string{"0.0.0.0/0"}},
		{"ipv6 catch-all", []string{"::/0"}, []string{"::/0"}},
		{"among valid ranges", []string{"10.0.0.0/8", "0.0.0.0/0"}, []string{"0.0.0.0/0"}},
		{"both", []string{"0.0.0.0/0", "::/0"}, []string{"0.0.0.0/0", "::/0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := catchAllProxyWarning(prefixes(t, tc.cidrs...))
			assert.Contains(t, got, "TRUSTED_PROXIES")
			for _, w := range tc.want {
				assert.Contains(t, got, w)
			}
			assert.NotContains(t, got, "10.0.0.0/8")
		})
	}
}

func TestCatchAllProxyWarning_QuietForSpecificRanges(t *testing.T) {
	assert.Empty(t, catchAllProxyWarning(nil))
	assert.Empty(t, catchAllProxyWarning(prefixes(t, "10.0.0.0/8", "172.16.0.0/12", "192.0.2.1/32", "fd00::/8", "::1/128")))
	// A /1 is wide but not a catch-all; only a zero-length prefix is flagged.
	assert.Empty(t, catchAllProxyWarning(prefixes(t, "0.0.0.0/1")))
}

// The value the operator writes in TRUSTED_PROXIES reaches the warning.
func TestCatchAllProxyWarning_FromTheEnvironment(t *testing.T) {
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 0.0.0.0/0")
	cfg, err := config.Load()
	assert.NoError(t, err)
	assert.Contains(t, catchAllProxyWarning(cfg.TrustedProxies), "0.0.0.0/0")
}
