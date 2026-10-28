package config

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDefaults(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "")
	t.Setenv("SSO_ALLOW_USERINFO_ONLY", "")
	t.Setenv("INVENTORY_TTL", "")
	t.Setenv("SERVER_ADDR", "")
	t.Setenv("DB_MIGRATE", "")
	t.Setenv("WATCHER_POLL_INTERVAL", "")
	t.Setenv("TRUSTED_PROXIES", "")
	t.Setenv("LIFECYCLE_SWEEP_INTERVAL", "")
	t.Setenv("CORS_ORIGINS", "")
	t.Setenv("REGISTRATION_ENABLED", "")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, ":8080", cfg.Addr)
	assert.Empty(t, cfg.CORSOrigins, "no origin is allowed cross-origin unless configured")
	assert.True(t, cfg.DBMigrate, "DB_MIGRATE defaults to true")
	assert.Equal(t, DefaultInventoryTTL, cfg.InventoryTTL)
	assert.Equal(t, DefaultSweepInterval, cfg.SweepInterval)
	assert.Equal(t, 30*24*time.Hour, cfg.SessionMaxAge, "sessions end 30 days after sign-in by default")
	assert.False(t, cfg.Watcher.Enable)
	assert.Equal(t, DefaultWatcherPoll, cfg.Watcher.PollInterval)
	assert.Equal(t, DefaultOSVEndpoint, cfg.Watcher.OSVEndpoint)
	assert.Equal(t, DefaultOSVVulnEndpoint, cfg.Watcher.OSVVulnEndpoint)
	assert.Empty(t, cfg.TrustedProxies, "forwarded headers are never trusted by default")
	assert.False(t, cfg.SSO.AllowUserInfoOnly, "userinfo-only OIDC downgrade is disabled by default")
	assert.True(t, cfg.RegistrationDisabled, "self-service registration is closed by default")
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

func TestLoad_RawRetentionDaysDefaultsToThirty(t *testing.T) {
	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, 30, cfg.RawRetentionDays)
}

func TestLoad_RawRetentionDaysZeroKeepsEverything(t *testing.T) {
	t.Setenv("RAW_RETENTION_DAYS", "0")
	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, 0, cfg.RawRetentionDays)
}

func TestLoad_RawRetentionDaysOverride(t *testing.T) {
	t.Setenv("RAW_RETENTION_DAYS", "90")
	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, 90, cfg.RawRetentionDays)
}

func TestLoad_RawRetentionDaysAtTheMaximumIsAccepted(t *testing.T) {
	t.Setenv("RAW_RETENTION_DAYS", "36500")
	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, 36500, cfg.RawRetentionDays)
}

// 106752 days is the first value whose Duration product overflows, so Load must refuse it at
// startup. Without the maximum the value reaches the sweep and its cutoff wraps into the future.
func TestLoad_RawRetentionDaysOverflowingWindowIsRefused(t *testing.T) {
	t.Setenv("RAW_RETENTION_DAYS", "106752")
	_, err := Load()
	assert.ErrorContains(t, err, "RAW_RETENTION_DAYS")
	assert.ErrorContains(t, err, "36500")
}

func TestLoad_InvalidRawRetentionDaysFails(t *testing.T) {
	for _, bad := range []string{"-1", "30d", "1.5", "forever"} {
		t.Run(bad, func(t *testing.T) {
			t.Setenv("RAW_RETENTION_DAYS", bad)
			_, err := Load()
			assert.ErrorContains(t, err, "RAW_RETENTION_DAYS")
		})
	}
}

func TestLoad_SessionMaxAgeOverride(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "")
	t.Setenv("SESSION_MAX_AGE", "168h")
	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, 168*time.Hour, cfg.SessionMaxAge)
}

func TestLoad_MalformedSessionMaxAgeFails(t *testing.T) {
	for _, bad := range []string{"not-a-duration", "0s", "-24h", "30"} {
		t.Run(bad, func(t *testing.T) {
			t.Setenv("WATCHER_ENABLE", "")
			t.Setenv("SESSION_MAX_AGE", bad)
			_, err := Load()
			assert.ErrorContains(t, err, "SESSION_MAX_AGE")
		})
	}
}

func TestWatcherConfig(t *testing.T) {
	t.Setenv("WATCHER_POLL_INTERVAL", "")
	t.Setenv("WATCHER_OSV_VULN_ENDPOINT", "")
	w, err := WatcherConfig()
	assert.NoError(t, err)
	assert.True(t, w.Enable)
	assert.Equal(t, DefaultOSVEndpoint, w.OSVEndpoint)
	assert.Equal(t, DefaultOSVVulnEndpoint, w.OSVVulnEndpoint,
		"the full-advisory endpoint defaults to the public OSV mirror")

	t.Setenv("WATCHER_OSV_ENDPOINT", "https://example.test/querybatch")
	t.Setenv("WATCHER_OSV_VULN_ENDPOINT", "https://example.test/vulns/{id}")
	w, err = WatcherConfig()
	assert.NoError(t, err)
	assert.Equal(t, "https://example.test/querybatch", w.OSVEndpoint)
	assert.Equal(t, "https://example.test/vulns/{id}", w.OSVVulnEndpoint,
		"an operator mirror keeps both feed endpoints inside one trust boundary")
}

func TestIntelConfig(t *testing.T) {
	t.Setenv("INTEL_EPSS_ENDPOINT", "")
	t.Setenv("INTEL_KEV_ENDPOINT", "")
	t.Setenv("INTEL_TTL", "")
	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, DefaultEPSSEndpoint, cfg.Intel.EPSSBaseURL)
	assert.Equal(t, DefaultKEVEndpoint, cfg.Intel.KEVCatalogURL)
	assert.Equal(t, DefaultIntelTTL, cfg.Intel.TTL)

	t.Setenv("INTEL_EPSS_ENDPOINT", "https://mirror.test/epss")
	t.Setenv("INTEL_KEV_ENDPOINT", "https://mirror.test/kev.json")
	t.Setenv("INTEL_TTL", "5m")
	cfg, err = Load()
	assert.NoError(t, err)
	assert.Equal(t, "https://mirror.test/epss", cfg.Intel.EPSSBaseURL)
	assert.Equal(t, "https://mirror.test/kev.json", cfg.Intel.KEVCatalogURL)
	assert.Equal(t, 5*time.Minute, cfg.Intel.TTL)

	t.Setenv("INTEL_TTL", "banana")
	_, err = Load()
	assert.ErrorContains(t, err, "INTEL_TTL")
}

func TestIntelEnabled(t *testing.T) {
	t.Setenv("INTEL_ENABLED", "")
	cfg, err := Load()
	require.NoError(t, err)
	assert.True(t, cfg.Intel.Enabled, "intel stays on unless an operator turns it off")

	for _, v := range []string{"false", "0", "FALSE"} {
		t.Setenv("INTEL_ENABLED", v)
		cfg, err = Load()
		require.NoError(t, err, v)
		assert.False(t, cfg.Intel.Enabled, v)
	}

	t.Setenv("INTEL_ENABLED", "true")
	cfg, err = Load()
	require.NoError(t, err)
	assert.True(t, cfg.Intel.Enabled)

	t.Setenv("INTEL_ENABLED", "off-ish")
	_, err = Load()
	assert.ErrorContains(t, err, "INTEL_ENABLED", "a typo must fail at startup, not leave outbound calls on")
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

func TestLoad_SSOAllowUserInfoOnlyOverride(t *testing.T) {
	t.Setenv("WATCHER_ENABLE", "")
	t.Setenv("SSO_ALLOW_USERINFO_ONLY", "true")

	cfg, err := Load()
	require.NoError(t, err)
	assert.True(t, cfg.SSO.AllowUserInfoOnly)
}

func TestLoad_SSOUnverifiedEmailIsOffUnlessExplicitlyTrue(t *testing.T) {
	tests := []struct {
		value   string
		want    bool
		invalid bool
	}{
		{"", false, false},
		{"true", true, false},
		{"false", false, false},
		{"yes", false, true},
		{"1", false, true},
		{"TRUE", false, true},
	}
	for _, name := range []string{"SSO_ALLOW_UNVERIFIED_EMAIL", "SSO_ALLOW_USERINFO_ONLY"} {
		for _, tc := range tests {
			t.Run(name+"="+tc.value, func(t *testing.T) {
				t.Setenv("WATCHER_ENABLE", "")
				t.Setenv(name, tc.value)

				cfg, err := Load()

				if tc.invalid {
					require.Error(t, err, "only the exact value true opts in; anything else stops startup")
					assert.Contains(t, err.Error(), name)
					return
				}
				require.NoError(t, err)
				got := cfg.SSO.AllowUnverifiedEmail
				if name == "SSO_ALLOW_USERINFO_ONLY" {
					got = cfg.SSO.AllowUserInfoOnly
				}
				assert.Equal(t, tc.want, got)
			})
		}
	}
}

// A boolean switch used to read anything but the exact string true as false,
// so RATE_LIMIT_ENABLED=1 silently turned every limiter off. ParseBool
// spellings are accepted, empty keeps the default and anything else fails.
func TestLoad_BooleanSwitchesParseOrFail(t *testing.T) {
	read := map[string]func(*Server) bool{
		"RATE_LIMIT_ENABLED": func(s *Server) bool { return s.RateLimit.Enable },
		"WATCHER_ENABLE":     func(s *Server) bool { return s.Watcher.Enable },
		"SSO_ENABLE":         func(s *Server) bool { return s.SSO.Enabled },
		"SSO_PUBLIC_CLIENT":  func(s *Server) bool { return s.SSO.PublicClient },
		"DB_MIGRATE":         func(s *Server) bool { return s.DBMigrate },
	}
	defaults := map[string]bool{"DB_MIGRATE": true}
	for name, get := range read {
		for _, tc := range []struct {
			value   string
			want    bool
			invalid bool
		}{
			{"", defaults[name], false},
			{"1", true, false},
			{"TRUE", true, false},
			{"True", true, false},
			{"0", false, false},
			{"false", false, false},
			{"yes", false, true},
			{"ture", false, true},
		} {
			t.Run(name+"="+tc.value, func(t *testing.T) {
				t.Setenv("WATCHER_ENABLE", "")
				t.Setenv(name, tc.value)

				cfg, err := Load()

				if tc.invalid {
					require.Error(t, err)
					assert.Contains(t, err.Error(), name)
					return
				}
				require.NoError(t, err)
				assert.Equal(t, tc.want, get(cfg))
			})
		}
	}
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

func TestLoad_RegistrationDefaultsClosed(t *testing.T) {
	t.Run("unset", func(t *testing.T) {
		value, wasSet := os.LookupEnv("REGISTRATION_ENABLED")
		require.NoError(t, os.Unsetenv("REGISTRATION_ENABLED"))
		t.Cleanup(func() {
			if wasSet {
				assert.NoError(t, os.Setenv("REGISTRATION_ENABLED", value))
			} else {
				assert.NoError(t, os.Unsetenv("REGISTRATION_ENABLED"))
			}
		})

		cfg, err := Load()

		require.NoError(t, err)
		assert.True(t, cfg.RegistrationDisabled)
	})

	t.Run("empty", func(t *testing.T) {
		t.Setenv("REGISTRATION_ENABLED", "")

		cfg, err := Load()

		require.NoError(t, err)
		assert.True(t, cfg.RegistrationDisabled)
	})
}

func TestLoad_RegistrationCanBeDisabled(t *testing.T) {
	for _, v := range []string{"false", "FALSE", "0"} {
		t.Run(v, func(t *testing.T) {
			t.Setenv("REGISTRATION_ENABLED", v)

			cfg, err := Load()

			assert.NoError(t, err)
			assert.True(t, cfg.RegistrationDisabled)
		})
	}
}

func TestLoad_RegistrationExplicitlyEnabled(t *testing.T) {
	t.Setenv("REGISTRATION_ENABLED", "true")

	cfg, err := Load()

	assert.NoError(t, err)
	assert.False(t, cfg.RegistrationDisabled)
}

func TestLoad_RegistrationTypoFailsFast(t *testing.T) {
	t.Setenv("REGISTRATION_ENABLED", "flase")

	_, err := Load()

	assert.ErrorContains(t, err, "REGISTRATION_ENABLED", "a typo must not silently leave registration open")
}

func TestLoad_RateLimitDefaults(t *testing.T) {
	t.Setenv("RATE_LIMIT_ENABLED", "")
	t.Setenv("RATE_LIMIT_RPS", "")
	t.Setenv("RATE_LIMIT_BURST", "")
	t.Setenv("RATE_LIMIT_AUTH_RPS", "")
	t.Setenv("RATE_LIMIT_AUTH_BURST", "")
	t.Setenv("RATE_LIMIT_LOGIN_PER_MINUTE", "")
	t.Setenv("RATE_LIMIT_LOGIN_BURST", "")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, DefaultRateLimitLoginPerMinute, cfg.RateLimit.LoginPerMinute)
	assert.Equal(t, DefaultRateLimitLoginBurst, cfg.RateLimit.LoginBurst)
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
	t.Setenv("RATE_LIMIT_LOGIN_PER_MINUTE", "30")
	t.Setenv("RATE_LIMIT_LOGIN_BURST", "8")

	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, 30, cfg.RateLimit.LoginPerMinute)
	assert.Equal(t, 8, cfg.RateLimit.LoginBurst)
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

func TestLoad_RateLimitLoginInvalidFailsWhenEnabled(t *testing.T) {
	t.Setenv("RATE_LIMIT_ENABLED", "true")
	t.Setenv("RATE_LIMIT_LOGIN_PER_MINUTE", "0")

	_, err := Load()
	assert.ErrorContains(t, err, "RATE_LIMIT_LOGIN_PER_MINUTE")
}

func TestLoad_RateLimitInvalidIgnoredWhenDisabled(t *testing.T) {
	t.Setenv("RATE_LIMIT_ENABLED", "")
	t.Setenv("RATE_LIMIT_RPS", "not-a-number")

	cfg, err := Load()
	assert.NoError(t, err, "a stray invalid var must not crash a dev server")
	assert.False(t, cfg.RateLimit.Enable)
}

func TestLoad_DBConnectTimeout(t *testing.T) {
	t.Run("defaults to thirty seconds", func(t *testing.T) {
		t.Setenv("DB_CONNECT_TIMEOUT", "")
		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, DefaultDBConnectTimeout, cfg.DBConnectTimeout)
		assert.Equal(t, 30*time.Second, cfg.DBConnectTimeout)
	})
	t.Run("a duration is used", func(t *testing.T) {
		t.Setenv("DB_CONNECT_TIMEOUT", "2m")
		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, 2*time.Minute, cfg.DBConnectTimeout)
	})
	t.Run("zero means a single attempt", func(t *testing.T) {
		t.Setenv("DB_CONNECT_TIMEOUT", "0s")
		cfg, err := Load()
		require.NoError(t, err)
		assert.Zero(t, cfg.DBConnectTimeout)
	})
	for _, bad := range []string{"banana", "-5s", "30"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			t.Setenv("DB_CONNECT_TIMEOUT", bad)
			_, err := Load()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "DB_CONNECT_TIMEOUT")
		})
	}
}

func TestLoad_IngestConcurrency(t *testing.T) {
	t.Run("unset leaves the router default", func(t *testing.T) {
		t.Setenv("INGEST_MAX_CONCURRENCY", "")
		cfg, err := Load()
		require.NoError(t, err)
		assert.Zero(t, cfg.IngestConcurrency)
	})
	t.Run("a positive number is used", func(t *testing.T) {
		t.Setenv("INGEST_MAX_CONCURRENCY", "3")
		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, 3, cfg.IngestConcurrency)
	})
	for _, bad := range []string{"0", "-1", "many"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			t.Setenv("INGEST_MAX_CONCURRENCY", bad)
			_, err := Load()
			require.Error(t, err, "a typo must fail at startup, not silently remove the limit")
			assert.Contains(t, err.Error(), "INGEST_MAX_CONCURRENCY")
		})
	}
}

func TestLoad_IngestMaxFindings(t *testing.T) {
	t.Run("unset leaves the built-in default", func(t *testing.T) {
		t.Setenv("INGEST_MAX_FINDINGS", "")
		cfg, err := Load()
		require.NoError(t, err)
		assert.Zero(t, cfg.IngestMaxFindings)
	})
	t.Run("a positive number is used", func(t *testing.T) {
		t.Setenv("INGEST_MAX_FINDINGS", "5000")
		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, 5000, cfg.IngestMaxFindings)
	})
	for _, bad := range []string{"0", "-1", "lots", "1.5"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			t.Setenv("INGEST_MAX_FINDINGS", bad)
			_, err := Load()
			require.Error(t, err, "a typo must fail at startup, not silently remove the limit")
			assert.Contains(t, err.Error(), "INGEST_MAX_FINDINGS")
		})
	}
}

func validServer() *Server {
	return &Server{
		DBURL:           "postgres://specht:pw@db:5432/specht",
		LogLevel:        "info",
		InventoryTTL:    time.Hour,
		SweepInterval:   time.Minute,
		SessionMaxAge:   time.Hour,
		Intel:           IntelConfig{TTL: time.Hour},
		DBMaxConns:      20,
		DBMinConns:      2,
		ShutdownTimeout: time.Minute,
	}
}

func TestServerValidate_AcceptsAWorkingConfiguration(t *testing.T) {
	assert.NoError(t, validServer().Validate())
}

func TestServerValidate_NamesEachProblemByItsVariable(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Server)
		want   string
	}{
		"no database":            {func(s *Server) { s.DBURL = "" }, "DATABASE_URL"},
		"unknown log level":      {func(s *Server) { s.LogLevel = "verbose" }, "LOG_LEVEL"},
		"zero inventory ttl":     {func(s *Server) { s.InventoryTTL = 0 }, "INVENTORY_TTL"},
		"negative intel ttl":     {func(s *Server) { s.Intel.TTL = -time.Second }, "INTEL_TTL"},
		"no connections":         {func(s *Server) { s.DBMaxConns = 0 }, "DB_MAX_CONNS"},
		"one connection":         {func(s *Server) { s.DBMaxConns, s.DBMinConns = 1, 0 }, "DB_MAX_CONNS"},
		"negative min":           {func(s *Server) { s.DBMinConns = -1 }, "DB_MIN_CONNS"},
		"min above max":          {func(s *Server) { s.DBMinConns, s.DBMaxConns = 30, 20 }, "DB_MIN_CONNS"},
		"zero session age":       {func(s *Server) { s.SessionMaxAge = 0 }, "SESSION_MAX_AGE"},
		"negative raw window":    {func(s *Server) { s.RawRetentionDays = -1 }, "RAW_RETENTION_DAYS"},
		"overflowing raw window": {func(s *Server) { s.RawRetentionDays = 106752 }, "RAW_RETENTION_DAYS"},
		"zero shutdown window":   {func(s *Server) { s.ShutdownTimeout = 0 }, "SHUTDOWN_TIMEOUT"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := validServer()
			tc.mutate(s)
			err := s.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestServerValidate_LogLevelIsCaseInsensitive(t *testing.T) {
	for _, level := range []string{"debug", "INFO", "Warn", "error"} {
		s := validServer()
		s.LogLevel = level
		assert.NoError(t, s.Validate(), level)
	}
}

func TestServerValidate_ReportsEveryProblemAtOnce(t *testing.T) {
	s := validServer()
	s.DBURL = ""
	s.LogLevel = "loud"
	s.DBMaxConns = 0

	err := s.Validate()

	require.Error(t, err)
	for _, want := range []string{"DATABASE_URL", "LOG_LEVEL", "DB_MAX_CONNS"} {
		assert.Contains(t, err.Error(), want, "one startup attempt shows everything to fix")
	}
}

func TestLoad_DBPoolAndShutdownSettings(t *testing.T) {
	t.Run("defaults", func(t *testing.T) {
		for _, k := range []string{"DB_MAX_CONNS", "DB_MIN_CONNS", "SHUTDOWN_TIMEOUT"} {
			t.Setenv(k, "")
		}
		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, 20, cfg.DBMaxConns)
		assert.Equal(t, 2, cfg.DBMinConns)
		assert.Equal(t, 150*time.Second, cfg.ShutdownTimeout, "longer than an ingest may run")
	})
	t.Run("overrides", func(t *testing.T) {
		t.Setenv("DB_MAX_CONNS", "50")
		t.Setenv("DB_MIN_CONNS", "5")
		t.Setenv("SHUTDOWN_TIMEOUT", "3m")
		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, 50, cfg.DBMaxConns)
		assert.Equal(t, 5, cfg.DBMinConns)
		assert.Equal(t, 3*time.Minute, cfg.ShutdownTimeout)
	})
	for name, env := range map[string][2]string{
		"max not a number":    {"DB_MAX_CONNS", "lots"},
		"max negative":        {"DB_MAX_CONNS", "-3"},
		"min not a number":    {"DB_MIN_CONNS", "few"},
		"shutdown no unit":    {"SHUTDOWN_TIMEOUT", "30"},
		"shutdown not a time": {"SHUTDOWN_TIMEOUT", "soon"},
	} {
		t.Run("rejects "+name, func(t *testing.T) {
			t.Setenv(env[0], env[1])
			_, err := Load()
			require.Error(t, err)
			assert.Contains(t, err.Error(), env[0])
		})
	}
}

func TestLoad_IngestMemoryBudget(t *testing.T) {
	t.Run("unset leaves the server default", func(t *testing.T) {
		t.Setenv("INGEST_MEMORY_BUDGET", "")
		cfg, err := Load()
		require.NoError(t, err)
		assert.Zero(t, cfg.IngestMemoryBudget)
	})
	for in, want := range map[string]int64{
		"2147483648": 2 << 30,
		"2GiB":       2 << 30,
		"512MiB":     512 << 20,
		"1.5GiB":     3 << 29,
		"64KiB":      64 << 10,
		"1TiB":       1 << 40,
		"3GB":        3_000_000_000,
		"250MB":      250_000_000,
		"2gib":       2 << 30,
		" 2 GiB ":    2 << 30,
		"4096B":      4096,
	} {
		t.Run("parses "+in, func(t *testing.T) {
			t.Setenv("INGEST_MEMORY_BUDGET", in)
			cfg, err := Load()
			require.NoError(t, err)
			assert.Equal(t, want, cfg.IngestMemoryBudget)
		})
	}
	for _, bad := range []string{"0", "-1", "-2GiB", "0GiB", "lots", "GiB", "2GiBs", "2 parsecs", "1e3", "99999999999TiB", "0.0001B", "1.5"} {
		t.Run("rejects "+bad, func(t *testing.T) {
			t.Setenv("INGEST_MEMORY_BUDGET", bad)
			_, err := Load()
			require.Error(t, err, "a typo must fail at startup, not silently remove the limit")
			assert.Contains(t, err.Error(), "INGEST_MEMORY_BUDGET")
		})
	}
}

func validSSO() SSOConfig {
	return SSOConfig{
		Enabled:      true,
		ClientID:     "specht",
		ClientSecret: "s3cret",
		IssuerURL:    "https://idp.example.com",
		RedirectURI:  "https://specht.example.com/api/v1/auth/sso/callback",
	}
}

func TestServerValidate_SSODisabledNeedsNothing(t *testing.T) {
	s := validServer()
	s.SSO = SSOConfig{ClientSecret: "", IssuerURL: "not a url"}
	assert.NoError(t, s.Validate(), "SSO settings are only checked when SSO is enabled")
}

func TestServerValidate_AcceptsAWorkingSSOConfiguration(t *testing.T) {
	for name, mutate := range map[string]func(*SSOConfig){
		"https everywhere":              func(*SSOConfig) {},
		"loopback http issuer":          func(c *SSOConfig) { c.IssuerURL = "http://127.0.0.1:9000" },
		"localhost redirect":            func(c *SSOConfig) { c.RedirectURI = "http://localhost:8080/api/v1/auth/sso/callback" },
		"ipv6 loopback":                 func(c *SSOConfig) { c.RedirectURI = "http://[::1]:8080/cb" },
		"issuer with a path":            func(c *SSOConfig) { c.IssuerURL = "https://idp.example.com/realms/corp" },
		"public client opt-in":          func(c *SSOConfig) { c.ClientSecret, c.PublicClient = "", true },
		"public flag with a secret set": func(c *SSOConfig) { c.PublicClient = true },
	} {
		t.Run(name, func(t *testing.T) {
			s := validServer()
			s.SSO = validSSO()
			mutate(&s.SSO)
			assert.NoError(t, s.Validate())
		})
	}
}

func TestServerValidate_NamesEachSSOProblemByItsVariable(t *testing.T) {
	cases := map[string]struct {
		mutate func(*SSOConfig)
		want   string
	}{
		"no issuer":                  {func(c *SSOConfig) { c.IssuerURL = "" }, "SSO_ISSUER_URL"},
		"issuer without a scheme":    {func(c *SSOConfig) { c.IssuerURL = "idp.example.com" }, "SSO_ISSUER_URL"},
		"plain http issuer":          {func(c *SSOConfig) { c.IssuerURL = "http://idp.example.com" }, "SSO_ISSUER_URL"},
		"issuer without a host":      {func(c *SSOConfig) { c.IssuerURL = "https://" }, "SSO_ISSUER_URL"},
		"no client id":               {func(c *SSOConfig) { c.ClientID = "" }, "SSO_CLIENT_ID"},
		"blank client id":            {func(c *SSOConfig) { c.ClientID = "  " }, "SSO_CLIENT_ID"},
		"no redirect":                {func(c *SSOConfig) { c.RedirectURI = "" }, "SSO_REDIRECT_URI"},
		"relative redirect":          {func(c *SSOConfig) { c.RedirectURI = "/api/v1/auth/sso/callback" }, "SSO_REDIRECT_URI"},
		"redirect without a host":    {func(c *SSOConfig) { c.RedirectURI = "https:///cb" }, "SSO_REDIRECT_URI"},
		"plain http redirect":        {func(c *SSOConfig) { c.RedirectURI = "http://specht.example.com/cb" }, "SSO_REDIRECT_URI"},
		"redirect with other scheme": {func(c *SSOConfig) { c.RedirectURI = "ftp://specht.example.com/cb" }, "SSO_REDIRECT_URI"},
		"redirect with a fragment":   {func(c *SSOConfig) { c.RedirectURI = "https://specht.example.com/cb#x" }, "SSO_REDIRECT_URI"},
		"empty secret":               {func(c *SSOConfig) { c.ClientSecret = "" }, "SSO_CLIENT_SECRET"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := validServer()
			s.SSO = validSSO()
			tc.mutate(&s.SSO)
			err := s.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestServerValidate_EmptySecretMessagePointsAtThePublicClientSwitch(t *testing.T) {
	s := validServer()
	s.SSO = validSSO()
	s.SSO.ClientSecret = ""

	err := s.Validate()

	require.Error(t, err)
	assert.Contains(t, err.Error(), "SSO_PUBLIC_CLIENT")
}

func TestServerValidate_ReportsEverySSOProblemAtOnce(t *testing.T) {
	s := validServer()
	s.SSO = SSOConfig{Enabled: true}

	err := s.Validate()

	require.Error(t, err)
	for _, want := range []string{"SSO_ISSUER_URL", "SSO_CLIENT_ID", "SSO_REDIRECT_URI", "SSO_CLIENT_SECRET"} {
		assert.Contains(t, err.Error(), want)
	}
}

func TestLoad_SSOPublicClient(t *testing.T) {
	t.Setenv("SSO_PUBLIC_CLIENT", "")
	cfg, err := Load()
	require.NoError(t, err)
	assert.False(t, cfg.SSO.PublicClient, "a client secret is required unless the operator opts out")

	t.Setenv("SSO_PUBLIC_CLIENT", "true")
	cfg, err = Load()
	require.NoError(t, err)
	assert.True(t, cfg.SSO.PublicClient)
}

func TestLoad_FingerprintKeyIsDecodedFromHex(t *testing.T) {
	t.Setenv("FINGERPRINT_KEY", " 000102030405060708090a0b0c0d0e0f ")
	cfg, err := Load()
	assert.NoError(t, err)
	assert.Equal(t, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, cfg.FingerprintKey)
}

func TestLoad_FingerprintKeyUnsetLeavesTheKeyToTheDatabase(t *testing.T) {
	t.Setenv("FINGERPRINT_KEY", "")
	cfg, err := Load()
	assert.NoError(t, err)
	assert.Empty(t, cfg.FingerprintKey)
}

// The error must not repeat the value, which is a secret.
func TestLoad_InvalidFingerprintKeyFailsWithoutEchoingIt(t *testing.T) {
	for _, bad := range []string{"not-hex-at-all-not-hex-at-all-xx", "00ff", "abc"} {
		t.Run(bad, func(t *testing.T) {
			t.Setenv("FINGERPRINT_KEY", bad)
			_, err := Load()
			assert.ErrorContains(t, err, "FINGERPRINT_KEY")
			assert.NotContains(t, err.Error(), bad)
		})
	}
}

func TestIngestSlotsLeaveAConnectionFree(t *testing.T) {
	cases := map[string]struct {
		concurrency, maxConns, want int
	}{
		"default fits the default pool": {0, 20, 8},
		"setting fits the pool":         {12, 20, 12},
		"default above a small pool":    {0, 8, 7},
		"setting equal to the pool":     {20, 20, 19},
		"smallest pool":                 {0, 2, 1},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			s := validServer()
			s.IngestConcurrency, s.DBMaxConns = tc.concurrency, tc.maxConns
			assert.Equal(t, tc.want, s.IngestSlots(8))
		})
	}
}

func TestLoad_SSOAllowPrivateIssuerIsOffUnlessExplicitlyTrue(t *testing.T) {
	tests := []struct {
		value   string
		want    bool
		invalid bool
	}{
		{"", false, false},
		{"true", true, false},
		{"false", false, false},
		{"1", false, true},
		{"yes", false, true},
		{"TRUE", false, true},
	}
	for _, tc := range tests {
		t.Run("value="+tc.value, func(t *testing.T) {
			t.Setenv("WATCHER_ENABLE", "")
			t.Setenv("SSO_ALLOW_PRIVATE_ISSUER", tc.value)

			cfg, err := Load()

			if tc.invalid {
				require.Error(t, err, "only the exact value true opts in; anything else stops startup")
				assert.Contains(t, err.Error(), "SSO_ALLOW_PRIVATE_ISSUER")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, cfg.SSO.AllowPrivateIssuer)
		})
	}
}
