package cvedetail

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testCVE = "CVE-2024-3094"

const nvdFixture = `{
  "resultsPerPage": 1, "totalResults": 1,
  "vulnerabilities": [{"cve": {
    "id": "CVE-2024-3094",
    "published": "2024-03-29T17:15:21.150",
    "lastModified": "2025-02-01T10:00:00.000",
    "weaknesses": [
      {"source": "nvd@nist.gov", "type": "Primary", "description": [{"lang": "en", "value": "CWE-506"}]},
      {"source": "other", "type": "Secondary", "description": [{"lang": "en", "value": "NVD-CWE-Other"}]}
    ],
    "metrics": {
      "cvssMetricV40": [{"source": "cna@example.org", "type": "Secondary", "cvssData": {"version": "4.0", "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "baseScore": 9.3}}],
      "cvssMetricV31": [
        {"source": "cna@example.org", "type": "Secondary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": 8.1}},
        {"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "baseScore": 10.0}}
      ],
      "cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary", "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C", "baseScore": 10.0}}]
    },
    "references": [
      {"url": "https://www.openwall.com/lists/oss-security/2024/03/29/4"},
      {"url": "http://insecure.example.com/advisory"},
      {"url": "javascript:alert(1)"}
    ]
  }}]
}`

// tlsClient returns the production client with the test server's
// certificate trusted, so redirect and dial rules stay the real ones.
func tlsClient(t *testing.T, srv *httptest.Server, timeout time.Duration) *http.Client {
	t.Helper()
	c := NewHTTPClient(timeout, false)
	c.Transport.(*http.Transport).TLSClientConfig = srv.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return c
}

func TestNVD_FoundOrdersVersionsAndFiltersData(t *testing.T) {
	var gotKey, gotUA, gotQuery string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotUA, gotQuery = r.Header.Get("apiKey"), r.Header.Get("User-Agent"), r.URL.RawQuery
		_, _ = w.Write([]byte(nvdFixture))
	}))
	defer srv.Close()
	p := &NVD{BaseURL: srv.URL + "/rest/json/cves/2.0", APIKey: "nvd-key", Client: tlsClient(t, srv, 2*time.Second)}

	rec, err := p.Lookup(context.Background(), testCVE)
	require.NoError(t, err)
	assert.Equal(t, "nvd-key", gotKey, "the key travels in the apiKey header")
	assert.Equal(t, "Specht", gotUA)
	assert.Equal(t, "cveId="+testCVE, gotQuery, "only the CVE identifier is sent")

	require.Len(t, rec.CVSS, 4)
	assert.Equal(t, "4.0", rec.CVSS[0].Version)
	assert.Equal(t, CVSSRecord{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Score: 10, Source: "nvd@nist.gov", Type: "Primary"}, rec.CVSS[1],
		"primary scores come before secondary ones within a version")
	assert.Equal(t, "Secondary", rec.CVSS[2].Type)
	assert.Equal(t, "2.0", rec.CVSS[3].Version)
	assert.Equal(t, []string{"CWE-506"}, rec.CWEs, "NVD placeholders such as NVD-CWE-Other are dropped")
	assert.Equal(t, []string{"https://www.openwall.com/lists/oss-security/2024/03/29/4"}, rec.References, "only https references survive")
	require.NotNil(t, rec.Published)
	assert.Equal(t, time.Date(2024, 3, 29, 17, 15, 21, 150_000_000, time.UTC), *rec.Published)
	require.NotNil(t, rec.Modified)
}

func TestNVD_KeylessSendsNoKeyHeader(t *testing.T) {
	var sawHeader bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawHeader = r.Header["Apikey"]
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()
	p := &NVD{BaseURL: srv.URL, Client: tlsClient(t, srv, 2*time.Second)}
	_, err := p.Lookup(context.Background(), testCVE)
	require.ErrorIs(t, err, ErrNotFound, "an empty result list is a not-found answer")
	assert.False(t, sawHeader)
}

func TestNVD_RateLimitStatuses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		header string
		want   time.Duration
	}{
		{"403 without Retry-After", http.StatusForbidden, "", defaultRetryAfter},
		{"429 with seconds", http.StatusTooManyRequests, "120", 120 * time.Second},
		{"429 capped", http.StatusTooManyRequests, "999999", maxRetryAfter},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.header != "" {
					w.Header().Set("Retry-After", tc.header)
				}
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()
			p := &NVD{BaseURL: srv.URL, Client: tlsClient(t, srv, 2*time.Second)}
			_, err := p.Lookup(context.Background(), testCVE)
			var rl *RateLimitedError
			require.ErrorAs(t, err, &rl)
			assert.Equal(t, tc.want, rl.RetryAfter)
			assert.Equal(t, ErrKindRateLimited, ErrorKind(err))
		})
	}
}

func TestVulnCheck_SendsBearerAndReadsNVDShape(t *testing.T) {
	var auth, query string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth, query = r.Header.Get("Authorization"), r.URL.RawQuery
		inner := nvdFixture[strings.Index(nvdFixture, `{"cve": `)+len(`{"cve": `):]
		inner = inner[:strings.LastIndex(inner, "}}]")+1]
		_, _ = fmt.Fprintf(w, `{"_meta":{"total_documents":1},"data":[%s]}`, inner)
	}))
	defer srv.Close()
	p := &VulnCheck{BaseURL: srv.URL, APIKey: "vc-token", Client: tlsClient(t, srv, 2*time.Second)}
	rec, err := p.Lookup(context.Background(), testCVE)
	require.NoError(t, err)
	assert.Equal(t, "Bearer vc-token", auth)
	assert.Equal(t, "cve="+testCVE, query)
	assert.Len(t, rec.CVSS, 4)
	assert.Equal(t, []string{"CWE-506"}, rec.CWEs)
}

func TestVulnCheck_EmptyDataIsNotFound(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"data":[]}`))
	}))
	defer srv.Close()
	p := &VulnCheck{BaseURL: srv.URL, APIKey: "k", Client: tlsClient(t, srv, 2*time.Second)}
	_, err := p.Lookup(context.Background(), testCVE)
	require.ErrorIs(t, err, ErrNotFound)
}

func TestOSV_NormalizesBareV2AndReadsCWEs(t *testing.T) {
	var path string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		if !strings.HasSuffix(r.URL.Path, testCVE) {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"id":"CVE-2024-3094","published":"2024-03-29T17:15:21Z","modified":"2024-04-01T00:00:00Z",
			"severity":[{"type":"CVSS_V2","score":"AV:N/AC:L/Au:N/C:C/I:C/A:C"},{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"},{"type":"Ubuntu","score":"high"}],
			"references":[{"type":"WEB","url":"https://example.com/a"}],
			"database_specific":{"cwe_ids":["CWE-506"]}}`))
	}))
	defer srv.Close()
	p := &OSV{BaseURL: srv.URL + "/v1/vulns", Client: tlsClient(t, srv, 2*time.Second)}
	rec, err := p.Lookup(context.Background(), testCVE)
	require.NoError(t, err)
	assert.Equal(t, "/v1/vulns/"+testCVE, path)
	require.Len(t, rec.CVSS, 2)
	assert.Equal(t, "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C", rec.CVSS[0].Vector)
	assert.Equal(t, "2.0", rec.CVSS[0].Version)
	assert.Equal(t, "3.1", rec.CVSS[1].Version)
	assert.Equal(t, []string{"CWE-506"}, rec.CWEs)

	_, err = p.Lookup(context.Background(), "CVE-2024-0001")
	require.ErrorIs(t, err, ErrNotFound)
}

func TestProviders_FailureModes(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler http.HandlerFunc
		kind    string
	}{
		{"server error", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusBadGateway) }, ErrKind5xx},
		{"client error", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusUnauthorized) }, ErrKind4xx},
		{"malformed json", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"vulnerabilities": [`)) }, ErrKindDecode},
		{"wrong json type", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"vulnerabilities": "nope"}`)) }, ErrKindDecode},
		{"oversize body", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"vulnerabilities":[],"pad":"`))
			_, _ = w.Write([]byte(strings.Repeat("a", maxResponseBytes)))
			_, _ = w.Write([]byte(`"}`))
		}, ErrKindTooLarge},
		{"deeply nested json", func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(`{"x":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`))
		}, ErrKindDecode},
		{"slow server", func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
		}, ErrKindTimeout},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewTLSServer(tc.handler)
			defer srv.Close()
			p := &NVD{BaseURL: srv.URL, Client: tlsClient(t, srv, 300*time.Millisecond)}
			_, err := p.Lookup(context.Background(), testCVE)
			require.Error(t, err)
			assert.Equal(t, tc.kind, ErrorKind(err), "error: %v", err)
		})
	}
}

func TestProviders_RefuseRedirects(t *testing.T) {
	var targetHit bool
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		targetHit = true
		_, _ = w.Write([]byte(nvdFixture))
	}))
	defer target.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/elsewhere", http.StatusFound)
	}))
	defer srv.Close()
	p := &NVD{BaseURL: srv.URL, Client: tlsClient(t, srv, 2*time.Second)}
	_, err := p.Lookup(context.Background(), testCVE)
	require.Error(t, err)
	assert.False(t, targetHit, "a redirect must never be followed")
	assert.Contains(t, err.Error(), "redirects are not allowed")
}

func TestProviders_RefuseHTTPBaseURL(t *testing.T) {
	p := &NVD{BaseURL: "http://services.nvd.nist.gov/rest/json/cves/2.0", Client: NewHTTPClient(time.Second, false)}
	_, err := p.Lookup(context.Background(), testCVE)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "https")
}

func TestProviders_UntrustedCertificateIsTLSError(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	defer srv.Close()
	p := &NVD{BaseURL: srv.URL, Client: NewHTTPClient(2*time.Second, false)}
	_, err := p.Lookup(context.Background(), testCVE)
	require.Error(t, err)
	assert.Equal(t, ErrKindTLS, ErrorKind(err))
}

// TestProviders_ErrorsNeverCarryTheKey drives every failure path with a
// sentinel key that the server also echoes into its body and headers, and
// checks that no error string, wrapped or formatted, contains it.
func TestProviders_ErrorsNeverCarryTheKey(t *testing.T) {
	const sentinel = "SENTINEL-KEY-7f3a9c"
	handlers := map[string]http.HandlerFunc{
		"not found": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(sentinel))
		},
		"rate limited": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Retry-After", sentinel)
			w.WriteHeader(http.StatusTooManyRequests)
		},
		"server error": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"message":"bad key ` + sentinel + `"}`))
		},
		"malformed": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"x":"` + sentinel)) },
		"oversize": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(strings.Repeat(sentinel, maxResponseBytes/len(sentinel)+2)))
		},
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://evil.example.com/?k="+sentinel, http.StatusFound)
		},
		"timeout": func(w http.ResponseWriter, r *http.Request) {
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
		},
	}
	for name, h := range handlers {
		srv := httptest.NewTLSServer(h)
		client := tlsClient(t, srv, 300*time.Millisecond)
		providers := []Provider{
			&NVD{BaseURL: srv.URL, APIKey: sentinel, Client: client},
			&VulnCheck{BaseURL: srv.URL, APIKey: sentinel, Client: client},
		}
		for _, p := range providers {
			_, err := p.Lookup(context.Background(), testCVE)
			require.Error(t, err, "%s/%s", p.Name(), name)
			for _, s := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err), ErrorKind(err)} {
				assert.NotContains(t, s, sentinel, "%s/%s leaked the key", p.Name(), name)
			}
			for e := errors.Unwrap(err); e != nil; e = errors.Unwrap(e) {
				assert.NotContains(t, e.Error(), sentinel, "%s/%s leaked the key in a wrapped error", p.Name(), name)
			}
		}
		srv.Close()
	}
}

func TestNormalizeVectorAndMetrics(t *testing.T) {
	assert.Equal(t, "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", NormalizeVector(" (AV:N/AC:L/Au:N/C:P/I:P/A:P) "))
	assert.Equal(t, "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", NormalizeVector("AV:N/AC:L/Au:N/C:P/I:P/A:P"))
	assert.Equal(t, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", NormalizeVector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))

	assert.Equal(t, "3.0", VectorVersion("CVSS:3.0/AV:N"), "the version comes from the prefix")
	assert.Empty(t, VectorVersion("AV:N/AC:L"))

	score, ok := ScoreVector("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P")
	require.True(t, ok)
	assert.InDelta(t, 7.5, score, 0.001)
	_, ok = ScoreVector("CVSS:3.1/AV:X/AC:L")
	assert.False(t, ok)

	m := Metrics("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H/E:P/RL:O/MAV:L")
	require.Len(t, m, 11)
	assert.Equal(t, Metric{Group: GroupBase, Key: "AV", Value: "N"}, m[0])
	assert.Equal(t, Metric{Group: GroupBase, Key: "S", Value: "C"}, m[4])
	assert.Equal(t, Metric{Group: GroupTemporal, Key: "E", Value: "P"}, m[8])
	assert.Equal(t, Metric{Group: GroupEnvironmental, Key: "MAV", Value: "L"}, m[10])

	m4 := Metrics("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:A/CR:H/S:P/U:Red")
	groups := map[string]string{}
	for _, x := range m4 {
		groups[x.Key] = x.Group
	}
	assert.Equal(t, GroupBase, groups["SC"])
	assert.Equal(t, GroupThreat, groups["E"])
	assert.Equal(t, GroupEnvironmental, groups["CR"])
	assert.Equal(t, GroupSupplemental, groups["S"])
	assert.Equal(t, GroupSupplemental, groups["U"])

	m2 := Metrics("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P/E:F/CDP:H")
	assert.Equal(t, GroupBase, m2[2].Group)
	assert.Equal(t, GroupTemporal, m2[6].Group)
	assert.Equal(t, GroupEnvironmental, m2[7].Group)
}

func TestSeverityBand(t *testing.T) {
	assert.Equal(t, "critical", SeverityBand("3.1", 9.8))
	assert.Equal(t, "high", SeverityBand("4.0", 7.0))
	assert.Equal(t, "medium", SeverityBand("3.0", 4.0))
	assert.Equal(t, "low", SeverityBand("3.1", 0.1))
	assert.Equal(t, "none", SeverityBand("3.1", 0))
	assert.Equal(t, "high", SeverityBand("2.0", 10), "v2 has no critical band")
	assert.Equal(t, "low", SeverityBand("2.0", 3.9))
}

func TestValidCVEID(t *testing.T) {
	assert.True(t, ValidCVEID("CVE-2024-3094"))
	assert.True(t, ValidCVEID("CVE-2024-1234567"))
	for _, bad := range []string{"CVE-24-3094", "GHSA-xxxx-yyyy-zzzz", "CVE-2024-3094/../x", "CVE-2024-3094?x=1", ""} {
		assert.False(t, ValidCVEID(bad), bad)
	}
}
