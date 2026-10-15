package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/cvedetail"
	"github.com/minh-tg/specht/internal/port"
)

const cveTestFindingID = "00000000-0000-0000-0000-000000000021"

type fakeOccurrenceReader struct {
	occ []cvedetail.Occurrence
	err error
}

func (f *fakeOccurrenceReader) ListLatestCVEOccurrences(context.Context, string) ([]cvedetail.Occurrence, error) {
	return f.occ, f.err
}

type fakeIntelLookup map[string]IntelRecord

func (f fakeIntelLookup) LookupIntel(cve string) (IntelRecord, bool) {
	rec, ok := f[cve]
	return rec, ok
}

// fakeResolver records the need flag of each lookup and answers with a fixed
// list.
type fakeResolver struct {
	names   []string
	answer  []cvedetail.ProviderLookup
	err     error
	needs   []bool
	status  []cvedetail.ProviderStatus
	stateEr error
}

func (f *fakeResolver) Providers() []string { return f.names }

func (f *fakeResolver) Lookup(_ context.Context, _ string, need bool) ([]cvedetail.ProviderLookup, error) {
	f.needs = append(f.needs, need)
	if f.err != nil {
		return nil, f.err
	}
	if !need {
		out := make([]cvedetail.ProviderLookup, 0, len(f.names))
		for _, n := range f.names {
			out = append(out, cvedetail.ProviderLookup{Name: n, Status: cvedetail.LookupSkipped})
		}
		return out, nil
	}
	return f.answer, nil
}

func (f *fakeResolver) Status(context.Context) ([]cvedetail.ProviderStatus, error) {
	return f.status, f.stateEr
}

func newCVETestUsecases(vulnID string, occ []cvedetail.Occurrence, resolver CVEProviderResolver, intelRecs fakeIntelLookup) *Usecases {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(context.Context, string) (port.Finding, error) { return makeFindingRow(1), nil }
	fr.listDimensionsFn = func(context.Context, string) ([]port.FindingDimension, error) {
		return []port.FindingDimension{{Key: "package_name", Value: "xz"}, {Key: "vulnerability_id", Value: vulnID}}, nil
	}
	deps := CVEDetailDeps{Occurrences: &fakeOccurrenceReader{occ: occ}, Intel: intelRecs}
	if resolver != nil {
		deps.Providers = resolver
	}
	return New(Deps{Stores: memberFindingDeps(fr), CVEDetail: deps})
}

func reportOcc(tool string, observed time.Time, metadata string) cvedetail.Occurrence {
	rid := "5d5b0000-0000-0000-0000-000000000001"
	return cvedetail.Occurrence{ToolName: tool, ReportID: &rid, ObservedAt: observed, Metadata: []byte(metadata)}
}

var cveObserved = time.Date(2026, 10, 14, 8, 0, 0, 0, time.UTC)

func TestGetFindingCVE_NotCVE(t *testing.T) {
	uc := newCVETestUsecases("GHSA-xxxx-yyyy-zzzz", nil, nil, nil)
	_, err := uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
	require.ErrorIs(t, err, ErrNotCVE)
}

func TestGetFindingCVE_RequiresProjectAccess(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(context.Context, string) (port.Finding, error) { return makeFindingRow(1), nil }
	pr := &mockProjectRepo{}
	pr.isMemberFn = func(context.Context, string, string) (bool, error) { return false, nil }
	uc := New(Deps{Stores: &port.Stores{Findings: fr, Projects: pr}, CVEDetail: CVEDetailDeps{Occurrences: &fakeOccurrenceReader{}}})
	_, err := uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
	require.ErrorIs(t, err, ErrProjectAccessDenied)

	_, err = uc.GetFindingCVE(context.Background(), cveTestFindingID)
	require.ErrorIs(t, err, ErrProjectAccessDenied, "no identity, no access")
}

func TestGetFindingCVE_CompleteReportSkipsProviders(t *testing.T) {
	resolver := &fakeResolver{names: []string{"nvd"}}
	occ := reportOcc("trivy", cveObserved, `{
		"specht": {"cvss_all": [
			{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "score": 10, "source": "nvd"},
			{"version": "2.0", "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C", "score": 10, "source": "nvd"}
		], "cvss": {"Version": "3.1", "Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", "Score": 10}},
		"trivy.cwe_ids": ["CWE-506"],
		"trivy.published": "2024-03-29T17:15:21Z",
		"trivy.last_modified": "2025-01-01T00:00:00Z",
		"trivy.primary_url": "https://avd.aquasec.com/nvd/cve-2024-3094"
	}`)
	uc := newCVETestUsecases(testCVEID, []cvedetail.Occurrence{occ}, resolver, nil)

	resp, err := uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
	require.NoError(t, err)
	assert.Equal(t, []bool{false}, resolver.needs, "a complete report must not ask providers")
	assert.False(t, resp.Pending)
	assert.Equal(t, testCVEID, resp.CVEID)

	require.Len(t, resp.CVSS, 2, "cvss_all wins over the single legacy entry")
	v3 := resp.CVSS[0]
	assert.Equal(t, "3.1", v3.Version)
	assert.True(t, v3.Valid)
	require.NotNil(t, v3.BaseScore)
	assert.InDelta(t, 10.0, *v3.BaseScore, 0.001)
	require.NotNil(t, v3.Severity)
	assert.Equal(t, "critical", *v3.Severity)
	require.Len(t, v3.Metrics, 8)
	assert.Equal(t, cvedetail.Metric{Group: "base", Key: "AV", Value: "N"}, v3.Metrics[0])
	assert.Equal(t, cvedetail.Metric{Group: "base", Key: "S", Value: "C"}, v3.Metrics[4])
	assert.Equal(t, ProvenanceScanReport, v3.Provenance.Kind)
	assert.Equal(t, "trivy", v3.Provenance.Tool)
	assert.Equal(t, "nvd", v3.Provenance.Detail)
	require.NotNil(t, v3.Provenance.ReportID)
	require.NotNil(t, v3.Provenance.ObservedAt)
	assert.Equal(t, cveObserved, *v3.Provenance.ObservedAt)

	v2 := resp.CVSS[1]
	assert.Equal(t, "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C", v2.Vector, "a bare v2 vector gets its prefix")
	assert.Equal(t, "2.0", v2.Version)
	assert.True(t, v2.Valid)
	assert.Equal(t, "high", *v2.Severity, "v2 bands stop at high")

	require.Len(t, resp.CWEs, 1)
	assert.Equal(t, "CWE-506", resp.CWEs[0].ID)
	require.NotNil(t, resp.PublishedAt)
	assert.Equal(t, time.Date(2024, 3, 29, 17, 15, 21, 0, time.UTC), resp.PublishedAt.Value)
	require.NotNil(t, resp.ModifiedAt)
	require.Len(t, resp.References, 1)
	assert.Equal(t, "https://avd.aquasec.com/nvd/cve-2024-3094", resp.References[0].URL)

	assert.Equal(t, []CVEProviderState{
		{Name: "nvd", Status: cvedetail.LookupSkipped},
		{Name: "vulncheck", Status: cvedetail.LookupDisabled},
		{Name: "osv", Status: cvedetail.LookupDisabled},
	}, resp.Providers)
}

// TestGetFindingCVE_IncompleteRule pins decision 4: providers are asked when
// the reports carry no valid v3.0, v3.1 or v4.0 vector, or carry neither a
// CWE nor a published date.
func TestGetFindingCVE_IncompleteRule(t *testing.T) {
	const v31 = `"specht": {"cvss_all": [{"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8}]}`
	const v30 = `"specht": {"cvss_all": [{"version": "3.1", "vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "score": 9.8}]}`
	const v40 = `"specht": {"cvss_all": [{"version": "4.0", "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "score": 9.3}]}`
	for _, tc := range []struct {
		name     string
		metadata string
		need     bool
	}{
		{"v3.1 with cwe and date", `{` + v31 + `, "trivy.cwe_ids": ["CWE-79"], "trivy.published": "2024-01-01T00:00:00Z"}`, false},
		{"v3.1 with cwe only", `{` + v31 + `, "trivy.cwe_ids": ["CWE-79"]}`, false},
		{"v3.1 with date only", `{` + v31 + `, "trivy.published": "2024-01-01T00:00:00Z"}`, false},
		{"v3.0 counts as modern", `{` + v30 + `, "trivy.cwe_ids": ["CWE-79"]}`, false},
		{"v4.0 counts as modern", `{` + v40 + `, "trivy.cwe_ids": ["CWE-79"]}`, false},
		{"v3.1 without cwe or date", `{` + v31 + `}`, true},
		{"v2 only", `{"specht": {"cvss": {"Version": "2.0", "Vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P", "Score": 7.5}}, "trivy.cwe_ids": ["CWE-79"]}`, true},
		{"unparseable vector", `{"specht": {"cvss_all": [{"version": "3.1", "vector": "CVSS:3.1/AV:Q/AC:L", "score": 9.8}]}, "trivy.cwe_ids": ["CWE-79"]}`, true},
		{"no vector at all", `{"trivy.cwe_ids": ["CWE-79"], "trivy.published": "2024-01-01T00:00:00Z"}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resolver := &fakeResolver{names: []string{"nvd"}, answer: []cvedetail.ProviderLookup{{Name: "nvd", Status: cvedetail.LookupPending}}}
			uc := newCVETestUsecases(testCVEID, []cvedetail.Occurrence{reportOcc("trivy", cveObserved, tc.metadata)}, resolver, nil)
			resp, err := uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
			require.NoError(t, err)
			assert.Equal(t, []bool{tc.need}, resolver.needs)
			assert.Equal(t, tc.need, resp.Pending)
		})
	}
}

func TestGetFindingCVE_InvalidVectorKeepsReportedScore(t *testing.T) {
	occ := reportOcc("dependency-check", cveObserved, `{"specht": {"cvss": {"Version": "3.1", "Vector": "CVSS:3.1/AV:Q/AC:L", "Score": 7.2}}}`)
	uc := newCVETestUsecases(testCVEID, []cvedetail.Occurrence{occ}, nil, nil)
	resp, err := uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
	require.NoError(t, err)
	require.Len(t, resp.CVSS, 1)
	c := resp.CVSS[0]
	assert.False(t, c.Valid)
	assert.Nil(t, c.BaseScore)
	assert.Empty(t, c.Metrics)
	require.NotNil(t, c.ReportedScore)
	assert.InDelta(t, 7.2, *c.ReportedScore, 0.001)
	require.NotNil(t, c.Severity)
	assert.Equal(t, "high", *c.Severity)
}

func TestGetFindingCVE_WatcherOccurrence(t *testing.T) {
	occ := cvedetail.Occurrence{ToolName: "osv-batch", ObservedAt: cveObserved, Metadata: []byte(`{
		"cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		"published": "2024-03-29T17:15:21Z",
		"modified": "2024-04-01T00:00:00Z",
		"references": ["https://osv.dev/vulnerability/CVE-2024-3094", "http://plain.example.com"]
	}`)}
	resolver := &fakeResolver{names: []string{"nvd"}}
	uc := newCVETestUsecases(testCVEID, []cvedetail.Occurrence{occ}, resolver, nil)
	resp, err := uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
	require.NoError(t, err)
	require.Len(t, resp.CVSS, 1)
	assert.Equal(t, ProvenanceWatcher, resp.CVSS[0].Provenance.Kind)
	assert.Equal(t, "osv-batch", resp.CVSS[0].Provenance.Tool)
	assert.Equal(t, "osv", resp.CVSS[0].Provenance.Detail)
	assert.Nil(t, resp.CVSS[0].Provenance.ReportID)
	require.NotNil(t, resp.PublishedAt)
	assert.Equal(t, ProvenanceWatcher, resp.PublishedAt.Provenance.Kind)
	require.Len(t, resp.References, 1, "only https references are listed")
	assert.Equal(t, []bool{false}, resolver.needs, "a v3.1 vector and a date make the watcher data complete")
}

func TestGetFindingCVE_ProviderValuesSitBesideReportValues(t *testing.T) {
	fetched := time.Date(2026, 10, 15, 9, 0, 0, 0, time.UTC)
	providerPublished := time.Date(2024, 3, 1, 0, 0, 0, 0, time.UTC)
	resolver := &fakeResolver{
		names: []string{"nvd", "osv"},
		answer: []cvedetail.ProviderLookup{
			{Name: "nvd", Status: cvedetail.LookupFound, FetchedAt: &fetched, Record: &cvedetail.Record{
				CVEID:      testCVEID,
				CVSS:       []cvedetail.CVSSRecord{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Score: 10, Source: "nvd@nist.gov", Type: "Primary"}},
				CWEs:       []string{"CWE-506", "CWE-79"},
				Published:  &providerPublished,
				References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-3094"},
			}},
			{Name: "osv", Status: cvedetail.LookupSkipped},
		},
	}
	occ := reportOcc("grype", cveObserved, `{"specht": {"cvss": {"Version": "2.0", "Vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C", "Score": 10}}, "grype.cwe_ids": ["CWE-506"], "grype.published": "2024-03-29T17:15:21Z"}`)
	uc := newCVETestUsecases(testCVEID, []cvedetail.Occurrence{occ}, resolver, nil)

	resp, err := uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
	require.NoError(t, err)
	assert.Equal(t, []bool{true}, resolver.needs, "a v2-only report asks providers")
	assert.False(t, resp.Pending)

	require.Len(t, resp.CVSS, 2)
	assert.Equal(t, ProvenanceScanReport, resp.CVSS[0].Provenance.Kind, "report vectors come first")
	p := resp.CVSS[1].Provenance
	assert.Equal(t, ProvenanceProvider, p.Kind)
	assert.Equal(t, "nvd", p.Provider)
	assert.Equal(t, "nvd@nist.gov primary", p.Detail)
	require.NotNil(t, p.FetchedAt)
	assert.Equal(t, fetched, *p.FetchedAt)

	require.Len(t, resp.CWEs, 2)
	assert.Equal(t, ProvenanceScanReport, resp.CWEs[0].Provenance.Kind, "a CWE the report has keeps the report as its source")
	assert.Equal(t, "CWE-79", resp.CWEs[1].ID)
	assert.Equal(t, ProvenanceProvider, resp.CWEs[1].Provenance.Kind)
	assert.Equal(t, ProvenanceScanReport, resp.PublishedAt.Provenance.Kind, "a provider date never replaces the report's")
	require.Len(t, resp.References, 1)
	assert.Equal(t, "nvd", resp.References[0].Provenance.Provider)

	assert.Equal(t, []CVEProviderState{
		{Name: "nvd", Status: "found", FetchedAt: &fetched},
		{Name: "osv", Status: "skipped"},
		{Name: "vulncheck", Status: "disabled"},
	}, resp.Providers)
}

func TestGetFindingCVE_ProviderCacheFailureDoesNotFailTheRead(t *testing.T) {
	resolver := &fakeResolver{names: []string{"nvd"}, err: errors.New("db down")}
	uc := newCVETestUsecases(testCVEID, nil, resolver, nil)
	resp, err := uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
	require.NoError(t, err)
	assert.Equal(t, cvedetail.LookupError, resp.Providers[0].Status)
	assert.Empty(t, resp.CVSS)
	assert.NotNil(t, resp.CVSS, "empty lists are [] in JSON, never null")
	assert.NotNil(t, resp.CWEs)
	assert.NotNil(t, resp.References)
}

func TestGetFindingCVE_NoProvidersConfigured(t *testing.T) {
	uc := newCVETestUsecases(testCVEID, nil, nil, nil)
	resp, err := uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
	require.NoError(t, err)
	assert.False(t, resp.Pending)
	require.Len(t, resp.Providers, 3)
	for _, p := range resp.Providers {
		assert.Equal(t, cvedetail.LookupDisabled, p.Status)
	}
}

func TestGetFindingCVE_Intel(t *testing.T) {
	fetched := time.Date(2026, 10, 15, 7, 0, 0, 0, time.UTC)
	uc := newCVETestUsecases(testCVEID, nil, nil, fakeIntelLookup{testCVEID: {
		EPSS: 0.85, EPSSDate: "2026-10-14", EPSSPercentile: 0.991,
		KEV: true, KEVDateAdded: "2024-04-01", KEVDueDate: "2024-04-22", KEVRansomware: "Unknown",
		FetchedAt: fetched,
	}})
	resp, err := uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
	require.NoError(t, err)
	require.NotNil(t, resp.EPSS)
	assert.InDelta(t, 0.85, resp.EPSS.Probability, 1e-9)
	require.NotNil(t, resp.EPSS.Percentile)
	assert.InDelta(t, 0.991, *resp.EPSS.Percentile, 1e-9)
	assert.Equal(t, "2026-10-14", *resp.EPSS.Date)
	assert.Equal(t, CVEProvenance{Kind: ProvenanceFeed, Provider: "epss", FetchedAt: &fetched}, resp.EPSS.Provenance)
	require.NotNil(t, resp.KEV)
	assert.True(t, resp.KEV.Listed)
	assert.Equal(t, "2024-04-22", *resp.KEV.DueDate)
	assert.Equal(t, "Unknown", *resp.KEV.KnownRansomwareUse)

	uc = newCVETestUsecases(testCVEID, nil, nil, fakeIntelLookup{testCVEID: {EPSS: 0.01, EPSSDate: "2026-10-14"}})
	resp, err = uc.GetFindingCVE(memberSessionCtx(), cveTestFindingID)
	require.NoError(t, err)
	require.NotNil(t, resp.EPSS)
	assert.Nil(t, resp.EPSS.Percentile, "a feed without a percentile shows none")
	assert.Nil(t, resp.KEV, "KEV absence is not shown as a negative")
}

func TestGetAdminStatus_ListsCVEProviders(t *testing.T) {
	ar := &mockAdminRepo{overviewFn: func(context.Context) (port.AdminOverview, error) { return port.AdminOverview{}, nil }}
	uc := New(Deps{Stores: &port.Stores{Admin: ar}})
	status, err := uc.GetAdminStatus(context.Background())
	require.NoError(t, err)
	require.Len(t, status.CVEProviders, 3)
	for _, p := range status.CVEProviders {
		assert.False(t, p.Enabled)
	}

	resolver := &fakeResolver{names: []string{"nvd"}, status: []cvedetail.ProviderStatus{{Name: "nvd", Enabled: true, KeyConfigured: true}}, stateEr: errors.New("db down")}
	uc = New(Deps{Stores: &port.Stores{Admin: ar}, CVEDetail: CVEDetailDeps{Providers: resolver}})
	status, err = uc.GetAdminStatus(context.Background())
	require.NoError(t, err, "a status table read failure does not fail the admin page")
	require.Len(t, status.CVEProviders, 1)
	assert.True(t, status.CVEProviders[0].KeyConfigured)
}

const testCVEID = "CVE-2024-3094"
