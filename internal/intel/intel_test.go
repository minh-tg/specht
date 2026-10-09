package intel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/risk"
)

func writeJSON(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	_, err := w.Write([]byte(body))
	require.NoError(t, err)
}

func TestEPSSProvider_ParsesBatch(t *testing.T) {
	var gotQuery string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("cve")
		writeJSON(t, w, `{"status":"OK","data":[`+
			`{"cve":"CVE-2024-1111","epss":"0.004150000","percentile":"0.347370000","date":"2026-09-04"},`+
			`{"cve":"CVE-2024-9999","epss":"0.912340000","percentile":"0.998760000","date":"2026-09-04"}]}`)
	}))
	defer srv.Close()

	p := &EPSSProvider{BaseURL: srv.URL, Client: srv.Client()}
	records, err := p.Fetch(context.Background(), []string{"CVE-2024-1111", "CVE-2024-9999", "CVE-2024-0000"})
	require.NoError(t, err)
	require.Len(t, records, 2, "CVEs the feed does not know are absent, not zeroed")
	assert.Equal(t, "CVE-2024-1111,CVE-2024-9999,CVE-2024-0000", gotQuery)
	require.NotNil(t, records["CVE-2024-1111"].EPSS)
	assert.InDelta(t, 0.00415, *records["CVE-2024-1111"].EPSS, 1e-9)
	assert.Equal(t, "2026-09-04", records["CVE-2024-1111"].EPSSDate)
}

func TestEPSSProvider_StatusError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	p := &EPSSProvider{BaseURL: srv.URL, Client: srv.Client()}
	_, err := p.Fetch(context.Background(), []string{"CVE-2024-1111"})
	require.ErrorContains(t, err, "status 429")
}

func TestKEVProvider_MatchesSubset(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"title":"CISA Catalog","catalogVersion":"2026.09.04","dateReleased":"2026-09-04","count":2,"vulnerabilities":[`+
			`{"cveID":"CVE-2026-85046","dateAdded":"2026-09-04"},`+
			`{"cveID":"CVE-2024-1111","dateAdded":"2026-01-15"}]}`)
	}))
	defer srv.Close()

	p := &KEVProvider{CatalogURL: srv.URL, Client: srv.Client()}
	records, err := p.Fetch(context.Background(), []string{"CVE-2024-1111", "CVE-2024-0000"})
	require.NoError(t, err)
	require.Len(t, records, 1, "KEV absence is not a record")
	assert.True(t, records["CVE-2024-1111"].KEV)
	assert.Equal(t, "2026-01-15", records["CVE-2024-1111"].KEVAdded)
}

func TestKEVProvider_ReusesCatalogWithinTTL(t *testing.T) {
	var downloads atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		writeJSON(t, w, `{"vulnerabilities":[`+
			`{"cveID":"CVE-2024-1111","dateAdded":"2026-01-15"},`+
			`{"cveID":"CVE-2024-2222","dateAdded":"2026-02-01"}]}`)
	}))
	defer srv.Close()

	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	p := &KEVProvider{CatalogURL: srv.URL, Client: srv.Client(), TTL: time.Hour, Now: func() time.Time { return now }}

	first, err := p.Fetch(context.Background(), []string{"CVE-2024-1111"})
	require.NoError(t, err)
	assert.Equal(t, "2026-01-15", first["CVE-2024-1111"].KEVAdded)

	now = now.Add(59 * time.Minute)
	second, err := p.Fetch(context.Background(), []string{"CVE-2024-2222", "CVE-2024-0000"})
	require.NoError(t, err)
	require.Len(t, second, 1)
	assert.Equal(t, "2026-02-01", second["CVE-2024-2222"].KEVAdded)
	assert.EqualValues(t, 1, downloads.Load(), "a second lookup inside the TTL must not download again")

	now = now.Add(2 * time.Minute)
	_, err = p.Fetch(context.Background(), []string{"CVE-2024-1111"})
	require.NoError(t, err)
	assert.EqualValues(t, 2, downloads.Load(), "an expired catalog is downloaded again")
}

func TestKEVProvider_FailedRefreshKeepsCatalogAndRetries(t *testing.T) {
	var downloads atomic.Int32
	var fail atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downloads.Add(1)
		if fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		writeJSON(t, w, `{"vulnerabilities":[{"cveID":"CVE-2024-1111","dateAdded":"2026-01-15"}]}`)
	}))
	defer srv.Close()

	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	p := &KEVProvider{CatalogURL: srv.URL, Client: srv.Client(), TTL: time.Hour, Now: func() time.Time { return now }}
	_, err := p.Fetch(context.Background(), []string{"CVE-2024-1111"})
	require.NoError(t, err)

	now = now.Add(2 * time.Hour)
	fail.Store(true)
	_, err = p.Fetch(context.Background(), []string{"CVE-2024-1111"})
	require.ErrorContains(t, err, "status 503")

	fail.Store(false)
	records, err := p.Fetch(context.Background(), []string{"CVE-2024-1111"})
	require.NoError(t, err, "the next call retries the download")
	assert.True(t, records["CVE-2024-1111"].KEV)
	assert.EqualValues(t, 3, downloads.Load())
}

func TestStore_RefreshMergesAndServes(t *testing.T) {
	epssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"status":"OK","data":[{"cve":"CVE-2024-1111","epss":"0.5","percentile":"0.9","date":"2026-09-04"}]}`)
	}))
	defer epssSrv.Close()
	kevSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"title":"t","catalogVersion":"v","dateReleased":"d","count":1,"vulnerabilities":[{"cveID":"CVE-2024-1111","dateAdded":"2026-01-15"}]}`)
	}))
	defer kevSrv.Close()

	now := time.Now()
	current := now
	s := NewStore(time.Hour, func() time.Time { return current },
		&EPSSProvider{BaseURL: epssSrv.URL, Client: epssSrv.Client()},
		&KEVProvider{CatalogURL: kevSrv.URL, Client: kevSrv.Client()},
	)

	require.NoError(t, s.Refresh(context.Background(), []string{"CVE-2024-1111", "GHSA-1234", "not-a-cve"}))
	rec, stale, ok := s.Lookup("CVE-2024-1111")
	require.True(t, ok)
	assert.False(t, stale)
	require.NotNil(t, rec.EPSS)
	assert.InDelta(t, 0.5, *rec.EPSS, 1e-9)
	assert.True(t, rec.KEV)
	assert.ElementsMatch(t, []string{"epss", "kev"}, rec.Sources)
	_, _, ok = s.Lookup("GHSA-1234")
	assert.False(t, ok, "non-CVE identifiers are never fetched")

	// Past the TTL the record still serves, flagged stale.
	current = now.Add(2 * time.Hour)
	_, stale, ok = s.Lookup("CVE-2024-1111")
	require.True(t, ok)
	assert.True(t, stale)

	// KEV membership feeds the risk model.
	var sig risk.Signals
	got, applied := s.ApplyToSignals("CVE-2024-1111", &sig)
	require.True(t, applied)
	require.NotNil(t, sig.HasKnownExploit)
	assert.True(t, *sig.HasKnownExploit)
	assert.True(t, got.KEV)
	exp := risk.Score(sig)
	assert.Contains(t, exp.Missing, "cvss")
}

func TestStore_FailedRefreshKeepsLastKnown(t *testing.T) {
	var fail bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJSON(t, w, `{"status":"OK","data":[{"cve":"CVE-2024-1111","epss":"0.5","percentile":"0.9","date":"2026-09-04"}]}`)
	}))
	defer srv.Close()

	now := time.Now()
	s := NewStore(time.Hour, func() time.Time { return now },
		&EPSSProvider{BaseURL: srv.URL, Client: srv.Client()})

	require.NoError(t, s.Refresh(context.Background(), []string{"CVE-2024-1111"}))
	fail = true
	require.Error(t, s.Refresh(context.Background(), []string{"CVE-2024-1111"}))
	rec, _, ok := s.Lookup("CVE-2024-1111")
	require.True(t, ok, "failed refresh must not erase the last known record")
	require.NotNil(t, rec.EPSS)
	assert.InDelta(t, 0.5, *rec.EPSS, 1e-9)
}

func TestStore_PartialRefreshPreservesCachedSignals(t *testing.T) {
	var failKEV bool
	epssScore := 0.5
	epssSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"status":"OK","data":[{"cve":"CVE-2024-1111","epss":"`+`0.5`+`","percentile":"0.9","date":"2026-09-04"}]}`)
	}))
	defer epssSrv.Close()

	kevSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failKEV {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		writeJSON(t, w, `{"title":"t","catalogVersion":"v","dateReleased":"d","count":1,"vulnerabilities":[{"cveID":"CVE-2024-1111","dateAdded":"2026-01-15"}]}`)
	}))
	defer kevSrv.Close()

	now := time.Now()
	s := NewStore(time.Hour, func() time.Time { return now },
		&EPSSProvider{BaseURL: epssSrv.URL, Client: epssSrv.Client()},
		&KEVProvider{CatalogURL: kevSrv.URL, Client: kevSrv.Client(), Now: func() time.Time { return now }},
	)

	// Step 1: Initial refresh populates both EPSS and KEV
	require.NoError(t, s.Refresh(context.Background(), []string{"CVE-2024-1111"}))
	rec, _, ok := s.Lookup("CVE-2024-1111")
	require.True(t, ok)
	require.NotNil(t, rec.EPSS)
	assert.InDelta(t, epssScore, *rec.EPSS, 1e-9)
	assert.True(t, rec.KEV)
	assert.Equal(t, "2026-01-15", rec.KEVAdded)

	// Step 2: the KEV catalog has expired and the download fails, EPSS
	// succeeds. Cached KEV data must NOT be erased.
	now = now.Add(2 * time.Hour)
	failKEV = true
	err := s.Refresh(context.Background(), []string{"CVE-2024-1111"})
	require.Error(t, err)

	rec2, _, ok2 := s.Lookup("CVE-2024-1111")
	require.True(t, ok2)
	assert.True(t, rec2.KEV, "KEV membership must be preserved when KEV provider fails")
	assert.Equal(t, "2026-01-15", rec2.KEVAdded)
	require.NotNil(t, rec2.EPSS)
	assert.InDelta(t, 0.5, *rec2.EPSS, 1e-9)
}
