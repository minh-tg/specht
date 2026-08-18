package gate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockFindingsRepo struct {
	FindingsRepo
	findings []Finding
	err      error
}

func (m *mockFindingsRepo) ListBlockingFindings(ctx context.Context, projectID string, minSeverityRank int16) ([]Finding, error) {
	return m.findings, m.err
}

type mockWaiversRepo struct {
	WaiversRepo
	waivers []Waiver
	err     error
}

func (m *mockWaiversRepo) ListActiveWaivers(ctx context.Context, projectID string) ([]Waiver, error) {
	return m.waivers, m.err
}

func TestEvaluate_NoFindings_Pass(t *testing.T) {
	g := New(&mockFindingsRepo{}, &mockWaiversRepo{})
	d, err := g.Evaluate(context.Background(), "proj-1", 3)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, d.Status)
	assert.Empty(t, d.BlockedBy)
	assert.Equal(t, 0, d.WaivedCount)
	assert.Equal(t, 0, d.TotalBlocking)
}

func TestEvaluate_BlockingNoWaivers_Fail(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0001"},
		}},
		&mockWaiversRepo{},
	)
	d, err := g.Evaluate(context.Background(), "proj-1", 3)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, d.Status)
	assert.Equal(t, []string{"f1"}, d.BlockedBy)
	assert.Equal(t, 0, d.WaivedCount)
	assert.Equal(t, 1, d.TotalBlocking)
}

func TestEvaluate_AllWaived_Pass(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0001"},
		}},
		&mockWaiversRepo{waivers: []Waiver{
			{ID: "w1", Targets: []WaiverTarget{{FindingID: "f1"}}},
		}},
	)
	d, err := g.Evaluate(context.Background(), "proj-1", 3)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, d.Status)
	assert.Empty(t, d.BlockedBy)
	assert.Equal(t, 1, d.WaivedCount)
	assert.Equal(t, 1, d.TotalBlocking)
}

func TestEvaluate_MixedWaivedUnwaived_Fail(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0001"},
			{ID: "f2", CurrentSeverityRank: 3, Fingerprint: "CVE-2024-0002"},
			{ID: "f3", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0003"},
		}},
		&mockWaiversRepo{waivers: []Waiver{
			{ID: "w1", Targets: []WaiverTarget{{FindingID: "f1"}}},
			{ID: "w2", Targets: []WaiverTarget{{FindingID: "f3"}}},
		}},
	)
	d, err := g.Evaluate(context.Background(), "proj-1", 3)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, d.Status)
	assert.Equal(t, []string{"f2"}, d.BlockedBy)
	assert.Equal(t, 2, d.WaivedCount)
	assert.Equal(t, 3, d.TotalBlocking)
}

func TestEvaluate_ContextWaiver_Matching(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, EnvironmentID: "env-prod", TargetID: "app-api"},
			{ID: "f2", CurrentSeverityRank: 4, EnvironmentID: "env-staging", TargetID: "app-api"},
			{ID: "f3", CurrentSeverityRank: 4, EnvironmentID: "env-prod", TargetID: "app-worker"},
		}},
		&mockWaiversRepo{waivers: []Waiver{
			{ID: "w1", Contexts: []WaiverContext{
				{EnvironmentID: "env-prod", TargetID: "app-api"},
			}},
		}},
	)
	d, err := g.Evaluate(context.Background(), "proj-1", 3)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, d.Status)
	assert.Equal(t, []string{"f2", "f3"}, d.BlockedBy)
	assert.Equal(t, 1, d.WaivedCount)
	assert.Equal(t, 3, d.TotalBlocking)
}

func TestEvaluate_ContextOR_MultipleRows(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, EnvironmentID: "env-prod"},
			{ID: "f2", CurrentSeverityRank: 4, EnvironmentID: "env-staging"},
			{ID: "f3", CurrentSeverityRank: 4, EnvironmentID: "env-dev"},
		}},
		&mockWaiversRepo{waivers: []Waiver{
			{ID: "w1", Contexts: []WaiverContext{
				{EnvironmentID: "env-prod"},
				{EnvironmentID: "env-staging"},
			}},
		}},
	)
	d, err := g.Evaluate(context.Background(), "proj-1", 3)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, d.Status)
	assert.Equal(t, []string{"f3"}, d.BlockedBy)
	assert.Equal(t, 2, d.WaivedCount)
	assert.Equal(t, 3, d.TotalBlocking)
}

func TestEvaluate_ExpiredWaiver_TreatedAsUnwaived(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, FindingKind: "vulnerability"},
		}},
		&mockWaiversRepo{waivers: []Waiver{
			{ID: "w1", Conditions: []WaiverCondition{
				{Field: "finding_kind", Operator: "eq", Value: "iac_misconfig"},
			}},
		}},
	)
	d, err := g.Evaluate(context.Background(), "proj-1", 3)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, d.Status)
	assert.Equal(t, []string{"f1"}, d.BlockedBy)
	assert.Equal(t, 0, d.WaivedCount)
	assert.Equal(t, 1, d.TotalBlocking)
}

// TestEvaluate_CveWatcherGateMatrix asserts the CVE-watcher gate-policy contract
// at the repo-mock seam. The mocked ListBlockingFindings stands in for the
// gate queries (sqlc GateEval/CountBlockingFindings and listBlockingFindingsSQL),
// whose WHERE clause already filtered cve_watcher findings according to the
// project's cve_watcher_gate mode: 'require_triage' (default) drops watcher
// findings whose analysis_state is 'unanalyzed' (the untriaged marker),
// 'off' drops all watcher findings, and 'immediate' drops none. Each case
// below feeds Evaluate exactly the fixture set the queries return for that
// mode; the verdicts assert the end-to-end behavior of the seam.
func TestEvaluate_CveWatcherGateMatrix(t *testing.T) {
	const minRank = int16(3)

	scaFinding := Finding{ID: "s1", FindingKind: "sca", CurrentSeverityRank: 4, Fingerprint: "CVE-2026-1001"}
	watcherTriaged := Finding{ID: "w-triaged", FindingKind: "cve_watcher", CurrentSeverityRank: 4, Fingerprint: "CVE-2026-1002"}
	watcherUntriaged := Finding{ID: "w-untriaged", FindingKind: "cve_watcher", CurrentSeverityRank: 4, Fingerprint: "CVE-2026-1003"}

	// Dimension-based waiver scoped to the cve_watcher kind: the same
	// mechanism that already waives sca findings by kind (matchCondition on
	// finding_kind), no new waiver logic.
	watcherKindWaiver := []Waiver{
		{ID: "w-kind", Conditions: []WaiverCondition{
			{Field: "finding_kind", Operator: "eq", Value: "cve_watcher"},
		}},
	}

	for _, tc := range []struct {
		name     string
		mode     string
		findings []Finding // what the gate queries return for this mode
		waivers  []Waiver
		want     Status
		blocked  []string
		waived   int
		total    int
	}{
		{
			name: "require_triage drops untriaged watcher finding, sca unaffected",
			mode: "require_triage",
			// query result: untriaged watcher excluded, sca + triaged watcher kept
			findings: []Finding{scaFinding, watcherTriaged},
			want:     StatusFail,
			blocked:  []string{"s1", "w-triaged"},
			total:    2,
		},
		{
			name: "require_triage sca-only project gates exactly as before",
			mode: "require_triage",
			// query result: no watcher findings at all
			findings: []Finding{scaFinding},
			want:     StatusFail,
			blocked:  []string{"s1"},
			total:    1,
		},
		{
			name: "require_triage only untriaged watcher findings -> pass",
			mode: "require_triage",
			// query result: every watcher finding untriaged -> empty
			findings: []Finding{},
			want:     StatusPass,
			total:    0,
		},
		{
			name:     "immediate admits untriaged watcher finding",
			mode:     "immediate",
			findings: []Finding{scaFinding, watcherTriaged, watcherUntriaged},
			want:     StatusFail,
			blocked:  []string{"s1", "w-triaged", "w-untriaged"},
			total:    3,
		},
		{
			name:     "off drops every watcher finding, sca unaffected",
			mode:     "off",
			findings: []Finding{scaFinding},
			want:     StatusFail,
			blocked:  []string{"s1"},
			total:    1,
		},
		{
			name:     "off only watcher findings -> pass",
			mode:     "off",
			findings: []Finding{},
			want:     StatusPass,
			total:    0,
		},
		{
			name:     "require_triage triaged watcher waived by kind -> waived",
			mode:     "require_triage",
			findings: []Finding{scaFinding, watcherTriaged},
			waivers:  watcherKindWaiver,
			want:     StatusFail,
			blocked:  []string{"s1"},
			waived:   1,
			total:    2,
		},
		{
			name:     "immediate all watcher findings waived -> pass",
			mode:     "immediate",
			findings: []Finding{watcherTriaged, watcherUntriaged},
			waivers:  watcherKindWaiver,
			want:     StatusPass,
			waived:   2,
			total:    2,
		},
		{
			name:     "kind-scoped watcher waiver does not leak to sca",
			mode:     "immediate",
			findings: []Finding{scaFinding},
			waivers:  watcherKindWaiver,
			want:     StatusFail,
			blocked:  []string{"s1"},
			total:    1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := New(
				&mockFindingsRepo{findings: tc.findings},
				&mockWaiversRepo{waivers: tc.waivers},
			)
			d, err := g.Evaluate(context.Background(), "proj-1", minRank)
			require.NoError(t, err)
			assert.Equal(t, tc.want, d.Status)
			assert.Equal(t, tc.blocked, d.BlockedBy)
			assert.Equal(t, tc.waived, d.WaivedCount)
			assert.Equal(t, tc.total, d.TotalBlocking)
		})
	}
}
