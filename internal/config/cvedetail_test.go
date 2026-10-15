package config

import (
	"bytes"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clearCVEDetailEnv blanks every CVE_DETAIL_* variable so a developer's
// environment cannot leak into a case.
func clearCVEDetailEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"CVE_DETAIL_PROVIDERS", "CVE_DETAIL_NVD_API_KEY", "CVE_DETAIL_VULNCHECK_API_KEY",
		"CVE_DETAIL_NVD_BASE_URL", "CVE_DETAIL_VULNCHECK_BASE_URL", "CVE_DETAIL_OSV_BASE_URL",
		"CVE_DETAIL_ALLOW_PRIVATE_MIRROR", "CVE_DETAIL_TTL", "CVE_DETAIL_NEGATIVE_TTL",
		"CVE_DETAIL_TIMEOUT", "CVE_DETAIL_NVD_RPS", "CVE_DETAIL_VULNCHECK_RPS", "CVE_DETAIL_OSV_RPS",
		"WATCHER_ENABLE",
	} {
		t.Setenv(k, "")
	}
}

func TestCVEDetail_OffByDefault(t *testing.T) {
	clearCVEDetailEnv(t)
	cfg, err := Load()
	require.NoError(t, err)
	assert.False(t, cfg.CVEDetail.Enabled(), "air-gapped installs make no provider calls unless configured")
	assert.Empty(t, cfg.CVEDetail.Providers)
}

func TestCVEDetail_StraySettingsIgnoredWhileOff(t *testing.T) {
	clearCVEDetailEnv(t)
	t.Setenv("CVE_DETAIL_TTL", "banana")
	t.Setenv("CVE_DETAIL_NVD_BASE_URL", "http://insecure.example.com")
	_, err := Load()
	assert.NoError(t, err)
}

func TestCVEDetail_ParsesOrderedProvidersAndDefaults(t *testing.T) {
	clearCVEDetailEnv(t)
	t.Setenv("CVE_DETAIL_PROVIDERS", " NVD, osv ")
	cfg, err := Load()
	require.NoError(t, err)
	c := cfg.CVEDetail
	assert.Equal(t, []string{"nvd", "osv"}, c.Providers)
	assert.Equal(t, DefaultCVEDetailTTL, c.TTL)
	assert.Equal(t, DefaultCVEDetailNegativeTTL, c.NegativeTTL)
	assert.Equal(t, DefaultCVEDetailTimeout, c.Timeout)
	assert.InDelta(t, 0.16, c.RPS["nvd"], 1e-9, "keyless NVD stays under 5 requests per 30 seconds")
	assert.False(t, c.AllowPrivateMirror)
}

func TestCVEDetail_KeyRaisesNVDRateAndOverridesApply(t *testing.T) {
	clearCVEDetailEnv(t)
	t.Setenv("CVE_DETAIL_PROVIDERS", "nvd")
	t.Setenv("CVE_DETAIL_NVD_API_KEY", "k")
	t.Setenv("CVE_DETAIL_TTL", "12h")
	t.Setenv("CVE_DETAIL_NEGATIVE_TTL", "1h")
	t.Setenv("CVE_DETAIL_TIMEOUT", "3s")
	t.Setenv("CVE_DETAIL_OSV_RPS", "2.5")
	t.Setenv("CVE_DETAIL_NVD_BASE_URL", "https://nvd-mirror.internal/rest/json/cves/2.0")
	t.Setenv("CVE_DETAIL_ALLOW_PRIVATE_MIRROR", "true")
	cfg, err := Load()
	require.NoError(t, err)
	c := cfg.CVEDetail
	assert.InDelta(t, 1.6, c.RPS["nvd"], 1e-9)
	assert.InDelta(t, 2.5, c.RPS["osv"], 1e-9)
	assert.Equal(t, 12*time.Hour, c.TTL)
	assert.Equal(t, time.Hour, c.NegativeTTL)
	assert.Equal(t, 3*time.Second, c.Timeout)
	assert.Equal(t, "https://nvd-mirror.internal/rest/json/cves/2.0", c.NVDBaseURL)
	assert.True(t, c.AllowPrivateMirror)
}

func TestCVEDetail_RejectsBadSettings(t *testing.T) {
	for _, tc := range []struct {
		name string
		env  map[string]string
		want string
	}{
		{"unknown provider", map[string]string{"CVE_DETAIL_PROVIDERS": "nvd,shodan"}, `unknown provider "shodan"`},
		{"duplicate provider", map[string]string{"CVE_DETAIL_PROVIDERS": "nvd,NVD"}, "twice"},
		{"vulncheck without key", map[string]string{"CVE_DETAIL_PROVIDERS": "vulncheck"}, "CVE_DETAIL_VULNCHECK_API_KEY is required"},
		{"http base URL", map[string]string{"CVE_DETAIL_PROVIDERS": "nvd", "CVE_DETAIL_NVD_BASE_URL": "http://nvd.example.com"}, "CVE_DETAIL_NVD_BASE_URL must be an https URL"},
		{"credentials in base URL", map[string]string{"CVE_DETAIL_PROVIDERS": "osv", "CVE_DETAIL_OSV_BASE_URL": "https://user:pass@osv.example.com"}, "CVE_DETAIL_OSV_BASE_URL must be an https URL"},
		{"bad ttl", map[string]string{"CVE_DETAIL_PROVIDERS": "nvd", "CVE_DETAIL_TTL": "0s"}, "CVE_DETAIL_TTL must be a positive duration"},
		{"bad rps", map[string]string{"CVE_DETAIL_PROVIDERS": "nvd", "CVE_DETAIL_NVD_RPS": "-1"}, "CVE_DETAIL_NVD_RPS"},
		{"bad private flag", map[string]string{"CVE_DETAIL_PROVIDERS": "nvd", "CVE_DETAIL_ALLOW_PRIVATE_MIRROR": "maybe"}, "CVE_DETAIL_ALLOW_PRIVATE_MIRROR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearCVEDetailEnv(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			_, err := Load()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}

func TestCVEDetail_ErrorsAndPrintsNeverShowKeys(t *testing.T) {
	const sentinel = "SENTINEL-KEY-config"
	clearCVEDetailEnv(t)
	t.Setenv("CVE_DETAIL_PROVIDERS", "nvd,vulncheck")
	t.Setenv("CVE_DETAIL_NVD_API_KEY", sentinel)
	t.Setenv("CVE_DETAIL_VULNCHECK_API_KEY", sentinel)
	t.Setenv("CVE_DETAIL_NVD_BASE_URL", "http://x.example.com/?apiKey="+sentinel)
	_, err := Load()
	require.Error(t, err)
	assert.NotContains(t, err.Error(), sentinel, "a rejected URL is echoed without its query")

	t.Setenv("CVE_DETAIL_NVD_BASE_URL", "")
	cfg, err := Load()
	require.NoError(t, err)
	var buf bytes.Buffer
	slog.New(slog.NewTextHandler(&buf, nil)).Info("config", "cve_detail", cfg.CVEDetail)
	for _, s := range []string{buf.String(), fmt.Sprintf("%v", cfg.CVEDetail), fmt.Sprintf("%+v", cfg.CVEDetail), fmt.Sprintf("%#v", cfg.CVEDetail)} {
		assert.NotContains(t, s, sentinel)
	}
	assert.Contains(t, buf.String(), "nvd_key_configured=true")
}
