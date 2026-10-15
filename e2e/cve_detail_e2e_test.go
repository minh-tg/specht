//go:build e2e

package e2e

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// cveDetailBOM lists two CVEs and one GHSA with no ratings, CWEs or dates,
// so the report is incomplete for both CVEs whatever the parsers keep.
const cveDetailBOM = `{
  "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
  "components": [{"bom-ref": "pkg:generic/xz@5.6.0", "type": "library", "name": "xz", "version": "5.6.0", "purl": "pkg:generic/xz@5.6.0"}],
  "vulnerabilities": [
    {"id": "CVE-2024-3094", "affects": [{"ref": "pkg:generic/xz@5.6.0"}]},
    {"id": "CVE-2024-0001", "affects": [{"ref": "pkg:generic/xz@5.6.0"}]},
    {"id": "GHSA-aaaa-bbbb-cccc", "affects": [{"ref": "pkg:generic/xz@5.6.0"}]}
  ]
}`

const cveDetailNVDAnswer = `{"totalResults": 1, "vulnerabilities": [{"cve": {
  "id": "CVE-2024-3094", "published": "2024-03-29T17:15:21.150", "lastModified": "2025-02-01T10:00:00.000",
  "weaknesses": [{"description": [{"lang": "en", "value": "CWE-506"}]}],
  "metrics": {"cvssMetricV31": [{"source": "nvd@nist.gov", "type": "Primary",
    "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "baseScore": 10.0}}]},
  "references": [{"url": "https://www.openwall.com/lists/oss-security/2024/03/29/4"}]
}}]}`

// fakeNVD is an https NVD mirror on loopback. It answers CVE-2024-3094,
// returns an empty result for anything else, and records every request.
type fakeNVD struct {
	srv *httptest.Server

	mu      sync.Mutex
	queries []string
	keys    []string
	agents  []string
}

func startFakeNVD(t *testing.T) *fakeNVD {
	t.Helper()
	f := &fakeNVD{}
	f.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.queries = append(f.queries, r.URL.RawQuery)
		f.keys = append(f.keys, r.Header.Get("apiKey"))
		f.agents = append(f.agents, r.Header.Get("User-Agent"))
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("cveId") == "CVE-2024-3094" {
			_, _ = w.Write([]byte(cveDetailNVDAnswer))
			return
		}
		_, _ = w.Write([]byte(`{"totalResults": 0, "vulnerabilities": []}`))
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeNVD) requests() (queries, keys, agents []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.queries...), append([]string(nil), f.keys...), append([]string(nil), f.agents...)
}

// certFile writes the mirror's certificate where the server process trusts it
// through SSL_CERT_FILE.
func (f *fakeNVD) certFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "nvd-mirror.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw})
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

type cveDetailBody struct {
	CVEID   string `json:"cve_id"`
	Pending bool   `json:"pending"`
	CVSS    []struct {
		Version    string   `json:"version"`
		Vector     string   `json:"vector"`
		BaseScore  *float64 `json:"base_score"`
		Valid      bool     `json:"valid"`
		Provenance struct {
			Kind     string `json:"kind"`
			Provider string `json:"provider"`
			Detail   string `json:"detail"`
		} `json:"provenance"`
		Metrics []struct{ Group, Key, Value string } `json:"metrics"`
	} `json:"cvss"`
	CWEs []struct {
		ID         string `json:"id"`
		Provenance struct {
			Kind string `json:"kind"`
		} `json:"provenance"`
	} `json:"cwes"`
	PublishedAt *struct {
		Value      string `json:"value"`
		Provenance struct {
			Kind     string `json:"kind"`
			Provider string `json:"provider"`
		} `json:"provenance"`
	} `json:"published_at"`
	Providers []struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"providers"`
}

// TestE2E_CVEDetailsFromAProviderMirror runs the real server with NVD pointed
// at an https mirror on loopback. An ingest sends nothing out; the first read
// of an incomplete CVE answers at once with pending and schedules one
// background fetch; a later read lists the provider's values with their
// provenance; further reads come from the cache. The key never reaches the
// API, the admin page or the log.
func TestE2E_CVEDetailsFromAProviderMirror(t *testing.T) {
	const apiKey = "e2e-nvd-key-SENTINEL-4471"
	const setupToken = "cve-detail-setup-token-0001"
	nvd := startFakeNVD(t)
	srv := startFreshServer(t, "specht_cve_detail_"+randomHex(3),
		"SETUP_TOKEN="+setupToken,
		"CVE_DETAIL_PROVIDERS=nvd",
		"CVE_DETAIL_NVD_BASE_URL="+nvd.srv.URL+"/rest/json/cves/2.0",
		"CVE_DETAIL_NVD_API_KEY="+apiKey,
		"CVE_DETAIL_NVD_RPS=50",
		"CVE_DETAIL_ALLOW_PRIVATE_MIRROR=true",
		"SSL_CERT_FILE="+nvd.certFile(t),
	)

	status, _, raw := srv.do(t, http.MethodPost, "/api/v1/setup", "", map[string]any{
		"email": "cve-admin@example.com", "password": "correct-horse-battery", "token": setupToken,
	})
	require.Equal(t, http.StatusCreated, status, string(raw))
	var session struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(raw, &session))
	token := session.Token

	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/projects", token, map[string]any{"name": "CVE detail", "slug": "cve-detail"})
	require.Equal(t, http.StatusCreated, status, string(raw))
	status, _, raw = srv.do(t, http.MethodPost, "/api/v1/reports", token, map[string]any{
		"project": "cve-detail", "scanner": "sbom", "raw_data": json.RawMessage(cveDetailBOM),
	})
	require.Equal(t, http.StatusCreated, status, string(raw))
	queries, _, _ := nvd.requests()
	require.Empty(t, queries, "an ingest never calls a provider")

	status, _, raw = srv.do(t, http.MethodGet, "/api/v1/projects/cve-detail/findings?limit=50", token, nil)
	require.Equal(t, http.StatusOK, status, string(raw))
	var findings []struct {
		ID    string `json:"id"`
		Title string `json:"current_title"`
	}
	require.NoError(t, json.Unmarshal(raw, &findings))
	byVuln := map[string]string{}
	for _, f := range findings {
		for _, v := range []string{"CVE-2024-3094", "CVE-2024-0001", "GHSA-aaaa-bbbb-cccc"} {
			if strings.Contains(f.Title, v) {
				byVuln[v] = f.ID
			}
		}
	}
	require.Len(t, byVuln, 3, "findings: %s", raw)

	readCVE := func(id string) (int, cveDetailBody, string) {
		status, _, raw := srv.do(t, http.MethodGet, "/api/v1/findings/"+id+"/cve", token, nil)
		var body cveDetailBody
		if status == http.StatusOK {
			require.NoError(t, json.Unmarshal(raw, &body), string(raw))
		}
		return status, body, string(raw)
	}

	t.Run("a GHSA finding has no CVE details", func(t *testing.T) {
		status, _, raw := readCVE(byVuln["GHSA-aaaa-bbbb-cccc"])
		require.Equal(t, http.StatusNotFound, status)
		require.Contains(t, raw, `"not_cve"`)
	})

	t.Run("the first read is pending and the provider answer lands later", func(t *testing.T) {
		start := time.Now()
		status, first, raw := readCVE(byVuln["CVE-2024-3094"])
		require.Equal(t, http.StatusOK, status, raw)
		require.Less(t, time.Since(start), 2*time.Second, "the read never waits on the provider")
		require.Equal(t, "CVE-2024-3094", first.CVEID)
		require.NotEmpty(t, first.Providers)
		require.Equal(t, "nvd", first.Providers[0].Name)
		if first.Providers[0].Status != "found" {
			require.True(t, first.Pending, raw)
		}

		var got cveDetailBody
		require.Eventually(t, func() bool {
			_, got, _ = readCVE(byVuln["CVE-2024-3094"])
			return len(got.Providers) > 0 && got.Providers[0].Status == "found"
		}, 15*time.Second, 100*time.Millisecond, "the provider answer never landed:\n%s", srv.readLog())
		require.False(t, got.Pending)
		require.Len(t, got.CVSS, 1)
		c := got.CVSS[0]
		require.Equal(t, "3.1", c.Version)
		require.True(t, c.Valid)
		require.NotNil(t, c.BaseScore)
		require.InDelta(t, 10.0, *c.BaseScore, 0.001)
		require.Equal(t, "provider", c.Provenance.Kind, "a provider value is never shown as the scanner's")
		require.Equal(t, "nvd", c.Provenance.Provider)
		require.Equal(t, "nvd@nist.gov primary", c.Provenance.Detail)
		require.Len(t, c.Metrics, 8)
		require.Equal(t, "AV", c.Metrics[0].Key)
		require.Len(t, got.CWEs, 1)
		require.Equal(t, "CWE-506", got.CWEs[0].ID)
		require.Equal(t, "provider", got.CWEs[0].Provenance.Kind)
		require.NotNil(t, got.PublishedAt)
		require.Equal(t, "nvd", got.PublishedAt.Provenance.Provider)

		for range 3 {
			readCVE(byVuln["CVE-2024-3094"])
		}
		queries, keys, agents := nvd.requests()
		var forThis int
		for i, q := range queries {
			if q == "cveId=CVE-2024-3094" {
				forThis++
			}
			require.Equal(t, apiKey, keys[i], "the key travels in the apiKey header")
			require.Equal(t, "Specht", agents[i])
			require.NotContains(t, q, apiKey, "the key never goes in the URL")
		}
		require.Equal(t, 1, forThis, "later reads are served from the cache: %v", queries)
	})

	t.Run("a CVE the provider does not know is cached as not found", func(t *testing.T) {
		var got cveDetailBody
		require.Eventually(t, func() bool {
			_, got, _ = readCVE(byVuln["CVE-2024-0001"])
			return len(got.Providers) > 0 && got.Providers[0].Status == "not_found"
		}, 15*time.Second, 100*time.Millisecond, "the negative answer never landed:\n%s", srv.readLog())
		require.False(t, got.Pending)
		require.Empty(t, got.CVSS)
	})

	t.Run("the admin page shows the provider without its key", func(t *testing.T) {
		status, _, raw := srv.do(t, http.MethodGet, "/api/v1/admin/status", token, nil)
		require.Equal(t, http.StatusOK, status, string(raw))
		var body struct {
			CVEProviders []struct {
				Name          string  `json:"name"`
				Enabled       bool    `json:"enabled"`
				KeyConfigured bool    `json:"key_configured"`
				LastSuccessAt *string `json:"last_success_at"`
			} `json:"cve_providers"`
		}
		require.NoError(t, json.Unmarshal(raw, &body))
		require.NotEmpty(t, body.CVEProviders)
		require.Equal(t, "nvd", body.CVEProviders[0].Name)
		require.True(t, body.CVEProviders[0].Enabled)
		require.True(t, body.CVEProviders[0].KeyConfigured)
		require.NotNil(t, body.CVEProviders[0].LastSuccessAt)
		require.NotContains(t, string(raw), apiKey)
		require.NotContains(t, srv.readLog(), apiKey, "the key never reaches the log")
	})
}
