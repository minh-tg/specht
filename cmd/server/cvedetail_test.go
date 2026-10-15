package main

import (
	"context"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/config"
	"github.com/minh-tg/specht/internal/intel"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildCVEDetail_ProvidersInConfiguredOrder(t *testing.T) {
	_, resolver := buildCVEDetail(config.CVEDetailConfig{
		Providers: []string{"osv", "nvd"}, Timeout: time.Second,
		RPS: map[string]float64{"nvd": 0.16, "osv": 1},
	}, nil, nil)
	assert.Equal(t, []string{"osv", "nvd"}, resolver.Providers())

	_, off := buildCVEDetail(config.CVEDetailConfig{}, nil, nil)
	assert.False(t, off.Enabled(), "no providers listed means nothing is fetched")
}

type staticEPSS struct{}

func (staticEPSS) Name() string { return "epss" }

func (staticEPSS) Fetch(_ context.Context, ids []string) (map[string]intel.Record, error) {
	score := 0.42
	out := map[string]intel.Record{}
	for _, id := range ids {
		out[id] = intel.Record{
			CVEID: id, EPSS: &score, EPSSDate: "2026-10-14", EPSSPercentile: 0.991,
			KEV: true, KEVAdded: "2024-04-01", KEVDueDate: "2024-04-22", KEVRansomware: "Known",
		}
	}
	return out, nil
}

func TestIntelLookup_MapsTheCachedRecord(t *testing.T) {
	store := intel.NewStore(time.Hour, nil, staticEPSS{})
	l := intelLookup{store: store}
	_, ok := l.LookupIntel("CVE-2024-3094")
	assert.False(t, ok, "the lookup reads the cache and never fetches")

	require.NoError(t, store.Refresh(context.Background(), []string{"CVE-2024-3094"}))
	rec, ok := l.LookupIntel("CVE-2024-3094")
	require.True(t, ok)
	assert.InDelta(t, 0.42, rec.EPSS, 1e-9)
	assert.Equal(t, "2026-10-14", rec.EPSSDate)
	assert.InDelta(t, 0.991, rec.EPSSPercentile, 1e-9)
	assert.True(t, rec.KEV)
	assert.Equal(t, "2024-04-01", rec.KEVDateAdded)
	assert.Equal(t, "2024-04-22", rec.KEVDueDate)
	assert.Equal(t, "Known", rec.KEVRansomware)
	assert.False(t, rec.FetchedAt.IsZero())

	_, ok = intelLookup{}.LookupIntel("CVE-2024-3094")
	assert.False(t, ok)
}
