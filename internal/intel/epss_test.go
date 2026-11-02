package intel

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEPSSProvider_SkipsScoresOutsideTheUnitRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, `{"status":"OK","data":[`+
			`{"cve":"CVE-2024-1111","epss":"NaN","percentile":"0.5","date":"2026-09-04"},`+
			`{"cve":"CVE-2024-2222","epss":"7","percentile":"0.5","date":"2026-09-04"},`+
			`{"cve":"CVE-2024-3333","epss":"-Inf","percentile":"0.5","date":"2026-09-04"},`+
			`{"cve":"CVE-2024-4444","epss":"+Inf","percentile":"0.5","date":"2026-09-04"},`+
			`{"cve":"CVE-2024-5555","epss":"-0.1","percentile":"0.5","date":"2026-09-04"},`+
			`{"cve":"CVE-2024-6666","epss":"0.25","percentile":"0.5","date":"2026-09-04"}]}`)
	}))
	defer srv.Close()

	ids := []string{"CVE-2024-1111", "CVE-2024-2222", "CVE-2024-3333", "CVE-2024-4444", "CVE-2024-5555", "CVE-2024-6666"}
	p := &EPSSProvider{BaseURL: srv.URL, Client: srv.Client()}
	records, err := p.Fetch(context.Background(), ids)
	require.NoError(t, err)
	require.Len(t, records, 1, "bad rows are skipped, the good row is kept")
	require.NotNil(t, records["CVE-2024-6666"].EPSS)
	assert.InDelta(t, 0.25, *records["CVE-2024-6666"].EPSS, 1e-9)
}

type fixedProvider struct{ recs map[string]Record }

func (fixedProvider) Name() string { return "fixed" }

func (f fixedProvider) Fetch(context.Context, []string) (map[string]Record, error) {
	return f.recs, nil
}

func TestStore_DoesNotCacheANonFiniteScore(t *testing.T) {
	nan := math.NaN()
	ok := 0.5
	s := NewStore(time.Hour, time.Now, fixedProvider{recs: map[string]Record{
		"CVE-2024-1111": {CVEID: "CVE-2024-1111", EPSS: &nan, EPSSPercentile: 0.5},
		"CVE-2024-2222": {CVEID: "CVE-2024-2222", EPSS: &ok, EPSSPercentile: 0.5},
	}})
	require.NoError(t, s.Refresh(context.Background(), []string{"CVE-2024-1111", "CVE-2024-2222"}))

	bad, _, found := s.Lookup("CVE-2024-1111")
	require.True(t, found)
	assert.Nil(t, bad.EPSS)
	_, err := json.Marshal(bad)
	assert.NoError(t, err, "a cached record must always encode")

	good, _, found := s.Lookup("CVE-2024-2222")
	require.True(t, found)
	require.NotNil(t, good.EPSS)
}
