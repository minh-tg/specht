package config

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaults(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "")
	t.Setenv("INVENTORY_TTL", "")
	t.Setenv("SERVER_ADDR", "")
	t.Setenv("DB_MIGRATE", "")
	t.Setenv("WATCHER_POLL_INTERVAL", "")
	t.Setenv("TRUSTED_PROXIES", "")
	t.Setenv("LIFECYCLE_SWEEP_INTERVAL", "")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, ":8080", cfg.Addr)
	assert.True(t, cfg.DBMigrate, "DB_MIGRATE defaults to true")
	assert.Equal(t, DefaultInventoryTTL, cfg.InventoryTTL)
	assert.Equal(t, DefaultSweepInterval, cfg.SweepInterval)
	assert.False(t, cfg.Watcher.Enable)
	assert.Equal(t, DefaultWatcherPoll, cfg.Watcher.PollInterval)
	assert.Equal(t, DefaultOSVEndpoint, cfg.Watcher.OSVEndpoint)
	assert.Empty(t, cfg.TrustedProxies, "forwarded headers are never trusted by default")
}

func TestLoad_TrustedProxies(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8, 192.168.1.0/24")

	cfg, err := Load()
	assert.NoError(t, err)
	require.Len(t, cfg.TrustedProxies, 2)
	assert.Equal(t, netip.MustParsePrefix("10.0.0.0/8"), cfg.TrustedProxies[0])
	assert.Equal(t, netip.MustParsePrefix("192.168.1.0/24"), cfg.TrustedProxies[1])
}

func TestLoad_InvalidTrustedProxiesFails(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "")
	t.Setenv("TRUSTED_PROXIES", "10.0.0.0/8,not-a-cidr")

	_, err := Load()
	assert.ErrorContains(t, err, "TRUSTED_PROXIES")
	assert.ErrorContains(t, err, "not-a-cidr")
}

func TestLoad_MalformedWatcherSettingIgnoredWhenDisabled(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "false")
	t.Setenv("WATCHER_POLL_INTERVAL", "not-a-duration")
	cfg, err := Load()
	assert.NoError(t, err, "malformed optional watcher settings must not fail a disabled watcher")
	assert.False(t, cfg.Watcher.Enable)
}

func TestLoad_MalformedWatcherSettingFailsWhenEnabled(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "true")
	t.Setenv("WATCHER_POLL_INTERVAL", "not-a-duration")
	_, err := Load()
	assert.ErrorContains(t, err, "WATCHER_POLL_INTERVAL")
}

func TestLoad_InventoryTTLAndAddrOverrides(t *testing.T) {
	t.Setenv("INVENTORY_TTL", "48h")
	t.Setenv("SERVER_ADDR", ":9999")
	t.Setenv("WATCHER_ENABLE", "")
	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, time.Hour*48, cfg.InventoryTTL)
	assert.Equal(t, ":9999", cfg.Addr)
}

func TestLoad_SweepIntervalOverride(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "")
	t.Setenv("LIFECYCLE_SWEEP_INTERVAL", "1s")
	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, time.Second, cfg.SweepInterval)
}

func TestLoad_MalformedSweepIntervalFails(t *testing.T) {
	for _, bad := range []string{"not-a-duration", "0s", "-5s"} {
		t.Run(bad, func(t *testing.T) {
			t.Setenv("WATCHER_ENABLE", "")
			t.Setenv("LIFECYCLE_SWEEP_INTERVAL", bad)
			_, err := Load()
			assert.ErrorContains(t, err, "LIFECYCLE_SWEEP_INTERVAL")
		})
	}
}

func TestWatcherConfig(t *testing.T) {
	t.Setenv("WATCHER_POLL_INTERVAL", "")
	w, err := WatcherConfig()
	assert.NoError(t, err)
	assert.True(t, w.Enable)
	assert.Equal(t, DefaultOSVEndpoint, w.OSVEndpoint)

	t.Setenv("WATCHER_OSV_ENDPOINT", "https://example.test/querybatch")
	w, err = WatcherConfig()
	assert.NoError(t, err)
	assert.Equal(t, "https://example.test/querybatch", w.OSVEndpoint)
}

func TestLoad_SSOAllowedDomains(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "")
	t.Setenv("SSO_ALLOWED_DOMAINS", "Example.COM, example.org ")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, []string{"example.com", "example.org"}, cfg.SSO.AllowedDomains)
}

func TestLoad_SSOAllowedDomainsEmpty(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "")
	t.Setenv("SSO_ALLOWED_DOMAINS", "")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.Empty(t, cfg.SSO.AllowedDomains, "empty allowlist disables auto-provisioning")
}

func TestLoad_SSOGroupMapping(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "")
	t.Setenv("SSO_GROUPS_CLAIM", "roles")
	t.Setenv("SSO_ADMIN_GROUPS", "idp-admins, Platform-Admins ")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, "roles", cfg.SSO.GroupsClaim)
	assert.Equal(t, []string{"idp-admins", "Platform-Admins"}, cfg.SSO.AdminGroups, "group names stay case-sensitive")
}

func TestLoad_SSOGroupMappingDefaults(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "")
	t.Setenv("SSO_GROUPS_CLAIM", "")
	t.Setenv("SSO_ADMIN_GROUPS", "")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.Empty(t, cfg.SSO.GroupsClaim, "empty claim means the default groups claim")
	assert.Empty(t, cfg.SSO.AdminGroups, "empty admin groups disable elevation")
}

func TestLoad_RateLimitDefaults(t *testing.T) {
	t.Setenv("RATE_LIMIT_ENABLED", "")
	t.Setenv("RATE_LIMIT_RPS", "")
	t.Setenv("RATE_LIMIT_BURST", "")
	t.Setenv("RATE_LIMIT_AUTH_RPS", "")
	t.Setenv("RATE_LIMIT_AUTH_BURST", "")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.False(t, cfg.RateLimit.Enable, "rate limiting is opt-in")
	assert.Equal(t, DefaultRateLimitRPS, cfg.RateLimit.RPS)
	assert.Equal(t, DefaultRateLimitBurst, cfg.RateLimit.Burst)
	assert.Equal(t, DefaultRateLimitAuthRPS, cfg.RateLimit.AuthRPS)
	assert.Equal(t, DefaultRateLimitAuthBurst, cfg.RateLimit.AuthBurst)
}

func TestLoad_RateLimitOverrides(t *testing.T) {
	t.Setenv("RATE_LIMIT_ENABLED", "true")
	t.Setenv("RATE_LIMIT_RPS", "50")
	t.Setenv("RATE_LIMIT_BURST", "100")
	t.Setenv("RATE_LIMIT_AUTH_RPS", "5000")
	t.Setenv("RATE_LIMIT_AUTH_BURST", "10000")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.True(t, cfg.RateLimit.Enable)
	assert.Equal(t, 50, cfg.RateLimit.RPS)
	assert.Equal(t, 100, cfg.RateLimit.Burst)
	assert.Equal(t, 5000, cfg.RateLimit.AuthRPS)
	assert.Equal(t, 10000, cfg.RateLimit.AuthBurst)
}

func TestLoad_RateLimitInvalidFailsWhenEnabled(t *testing.T) {
	t.Setenv("RATE_LIMIT_ENABLED", "true")
	t.Setenv("RATE_LIMIT_RPS", "not-a-number")

	_, err := Load()
	assert.ErrorContains(t, err, "RATE_LIMIT_RPS")
}

func TestLoad_RateLimitInvalidIgnoredWhenDisabled(t *testing.T) {
	t.Setenv("RATE_LIMIT_ENABLED", "")
	t.Setenv("RATE_LIMIT_RPS", "not-a-number")

	cfg, err := Load()
	assert.NoError(t, err, "a stray invalid var must not crash a dev server")
	assert.False(t, cfg.RateLimit.Enable)
}
