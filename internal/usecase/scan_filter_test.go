package usecase

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/port"
)

// scanFilterHarness returns the ingest stack of revisionHarness and the report
// input the store receives.
func scanFilterHarness(t *testing.T) (*Usecases, *port.CreateReportInput) {
	t.Helper()
	uc, rr, _, _ := revisionHarness(t, func(context.Context, string, string, string) (port.Finding, error) {
		return port.Finding{}, port.ErrNotFound
	})
	created := &port.CreateReportInput{}
	rr.createFn = func(_ context.Context, arg port.CreateReportInput) (port.Report, error) {
		*created = arg
		return makeReport(), nil
	}
	return uc, created
}

func TestIngestReport_StoresTheScanFilterOnTheReport(t *testing.T) {
	uc, created := scanFilterHarness(t)

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
		ScanFilter:  domain.ScanFilter{Severities: []string{"CRITICAL", "High"}, FixableOnly: true},
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"high", "critical"}, created.FilterSeverities)
	assert.True(t, created.FilterFixableOnly)
}

func TestIngestReport_UnfilteredScanStoresNoFilter(t *testing.T) {
	uc, created := scanFilterHarness(t)

	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
	})
	require.NoError(t, err)

	assert.Nil(t, created.FilterSeverities, "no severity filter is NULL, not an empty list")
	assert.False(t, created.FilterFixableOnly)
}

func TestIngestReport_UnknownScanFilterSeverityRejected(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.IngestReport(context.Background(), IngestReportInput{
		ProjectSlug: "my-app",
		Scanner:     "trivy",
		RawData:     json.RawMessage(`{"test": true}`),
		ScanFilter:  domain.ScanFilter{Severities: []string{"severe"}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "scan_filter")
}

func TestToReport_MapsTheScanFilter(t *testing.T) {
	r := makeReport()
	assert.Nil(t, toReport(r, 0).ScanFilter, "an unfiltered scan has no scan_filter")

	r.FilterSeverities = []string{"high", "critical"}
	resp := toReport(r, 0)
	require.NotNil(t, resp.ScanFilter)
	assert.Equal(t, []string{"high", "critical"}, resp.ScanFilter.Severities)
	assert.False(t, resp.ScanFilter.FixableOnly)

	// Only a fixable filter still reads as an empty list, never null.
	r.FilterSeverities = nil
	r.FilterFixableOnly = true
	resp = toReport(r, 0)
	require.NotNil(t, resp.ScanFilter)
	assert.NotNil(t, resp.ScanFilter.Severities)
	assert.Empty(t, resp.ScanFilter.Severities)
	assert.True(t, resp.ScanFilter.FixableOnly)

	body, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.Contains(t, string(body), `"scan_filter":{"severities":[],"fixable_only":true}`)
}
