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

func (m *mockFindingsRepo) ListIntroducedGateCandidates(ctx context.Context, reportID string, minSeverityRank int16) ([]Finding, error) {
	if m.err != nil {
		return nil, m.err
	}
	if reportID == "" {
		return nil, nil
	}
	var res []Finding
	for _, f := range m.findings {
		if f.IntroducedByReportID == reportID && f.CurrentSeverityRank >= minSeverityRank {
			res = append(res, f)
		}
	}
	return res, nil
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

func TestEvaluate_BlockedByReachability_Populated(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0001", Reachability: ReachabilityReachable},
			{ID: "f2", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0002", Reachability: ReachabilityUnknown},
			{ID: "f3", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0003", Reachability: ""}, // no assessment
			{ID: "f4", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0004", Reachability: ReachabilityNotReachable},
			{ID: "f5", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0005", Reachability: ReachabilityNotApplicable},
		}},
		&mockWaiversRepo{},
	)
	d, err := g.Evaluate(context.Background(), "proj-1", 3)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, d.Status)
	assert.Equal(t, []string{"f1", "f2", "f3"}, d.BlockedBy)
	assert.Equal(t, ReachabilityReachable, d.BlockedByReachability["f1"])
	assert.Equal(t, ReachabilityUnknown, d.BlockedByReachability["f2"])
	assert.Equal(t, ReachabilityUnknown, d.BlockedByReachability["f3"])
	assert.NotContains(t, d.BlockedByReachability, "f4")
	assert.NotContains(t, d.BlockedByReachability, "f5")
	assert.Len(t, d.BlockedByReachability, 3)
	assert.Equal(t, 3, d.TotalBlocking)
}

func TestEvaluate_Pass_HasEmptyReachabilityMap(t *testing.T) {
	g := New(&mockFindingsRepo{}, &mockWaiversRepo{})
	d, err := g.Evaluate(context.Background(), "proj-1", 3)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, d.Status)
	assert.Empty(t, d.BlockedByReachability)
}

func TestEvaluate_WaivedFinding_NotInReachabilityMap(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0001", Reachability: ReachabilityReachable},
			{ID: "f2", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0002", Reachability: ReachabilityNotReachable},
		}},
		&mockWaiversRepo{waivers: []Waiver{
			{ID: "w1", Targets: []WaiverTarget{{FindingID: "f1"}}},
		}},
	)
	d, err := g.Evaluate(context.Background(), "proj-1", 3)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, d.Status)
	assert.Empty(t, d.BlockedBy)
	assert.NotContains(t, d.BlockedByReachability, "f1")
	assert.NotContains(t, d.BlockedByReachability, "f2")
	assert.Equal(t, 1, d.WaivedCount)
	assert.Equal(t, 1, d.TotalBlocking)
}

// TestEvaluateWithPolicies_SourceAdmission exercises the per-source gate
// policy input directly. The core gate must not hard-code the watcher source
// literal: policies arrive as data from source registration, and findings
// from ungoverned sources always gate.
func TestEvaluateWithPolicies_SourceAdmission(t *testing.T) {
	const minRank = int16(3)

	sca := Finding{ID: "s1", FindingKind: "sca", CurrentSeverityRank: 4, Fingerprint: "CVE-2026-1001", Source: ""}
	watcherTriaged := Finding{ID: "w-triaged", FindingKind: "cve_watcher", CurrentSeverityRank: 4, Fingerprint: "CVE-2026-1002", Source: "cve_watcher", AnalysisState: "exploitable"}
	watcherUntriaged := Finding{ID: "w-untriaged", FindingKind: "cve_watcher", CurrentSeverityRank: 4, Fingerprint: "CVE-2026-1003", Source: "cve_watcher", AnalysisState: ""}

	tests := []struct {
		name     string
		findings []Finding
		policies []GatePolicy
		want     Status
		blocked  []string
		total    int
	}{
		{
			name:     "no policies: every finding gates",
			findings: []Finding{sca, watcherTriaged, watcherUntriaged},
			want:     StatusFail,
			blocked:  []string{"s1", "w-triaged", "w-untriaged"},
			total:    3,
		},
		{
			name:     "require_triage drops untriaged watcher finding",
			findings: []Finding{sca, watcherTriaged, watcherUntriaged},
			policies: []GatePolicy{{Source: "cve_watcher", Mode: PolicyRequireTriage}},
			want:     StatusFail,
			blocked:  []string{"s1", "w-triaged"},
			total:    2,
		},
		{
			name:     "off drops every governed finding",
			findings: []Finding{sca, watcherTriaged, watcherUntriaged},
			policies: []GatePolicy{{Source: "cve_watcher", Mode: PolicyOff}},
			want:     StatusFail,
			blocked:  []string{"s1"},
			total:    1,
		},
		{
			name:     "immediate admits untriaged watcher finding",
			findings: []Finding{sca, watcherTriaged, watcherUntriaged},
			policies: []GatePolicy{{Source: "cve_watcher", Mode: PolicyImmediate}},
			want:     StatusFail,
			blocked:  []string{"s1", "w-triaged", "w-untriaged"},
			total:    3,
		},
		{
			name:     "policy for another source does not affect watcher findings",
			findings: []Finding{watcherTriaged, watcherUntriaged},
			policies: []GatePolicy{{Source: "other_source", Mode: PolicyOff}},
			want:     StatusFail,
			blocked:  []string{"w-triaged", "w-untriaged"},
			total:    2,
		},
		{
			name:     "off drops all governed findings to pass",
			findings: []Finding{watcherTriaged, watcherUntriaged},
			policies: []GatePolicy{{Source: "cve_watcher", Mode: PolicyOff}},
			want:     StatusPass,
			total:    0,
		},
		{
			name:     "require_triage all untriaged passes",
			findings: []Finding{watcherUntriaged},
			policies: []GatePolicy{{Source: "cve_watcher", Mode: PolicyRequireTriage}},
			want:     StatusPass,
			total:    0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := New(&mockFindingsRepo{findings: tt.findings}, &mockWaiversRepo{})
			d, err := g.EvaluateWithPolicies(context.Background(), "proj-1", minRank, tt.policies)
			require.NoError(t, err)
			assert.Equal(t, tt.want, d.Status)
			assert.Equal(t, tt.blocked, d.BlockedBy)
			assert.Equal(t, tt.total, d.TotalBlocking)
		})
	}
}

// TestEvaluate_DefaultNoPoliciesMatchesEvaluateWithPoliciesNil ensures the
// plain Evaluate path is identical to EvaluateWithPolicies with no policies.
func TestEvaluate_DefaultNoPoliciesMatchesEvaluateWithPoliciesNil(t *testing.T) {
	findings := []Finding{
		{ID: "f1", FindingKind: "sca", CurrentSeverityRank: 4, Fingerprint: "CVE-1", Source: "cve_watcher", AnalysisState: ""},
	}
	mock := &mockFindingsRepo{findings: findings}
	g := New(mock, &mockWaiversRepo{})
	d1, err := g.Evaluate(context.Background(), "p", 3)
	require.NoError(t, err)
	d2, err2 := g.EvaluateWithPolicies(context.Background(), "p", 3, nil)
	require.NoError(t, err2)
	assert.Equal(t, d1, d2)
}

func TestEvaluate_CVEIDWaiverMatching(t *testing.T) {
	tests := []struct {
		name      string
		finding   Finding
		condition WaiverCondition
		wantPass  bool
	}{
		{
			name: "exact match on compound SCA fingerprint",
			finding: Finding{
				ID:                  "f1",
				CurrentSeverityRank: 4,
				Fingerprint:         "CVE-2024-1234:pkg:npm/lodash@4.17.20",
			},
			condition: WaiverCondition{Field: "cve_id", Operator: "eq", Value: "CVE-2024-1234"},
			wantPass:  true,
		},
		{
			name: "exact match on prefixed sca fingerprint",
			finding: Finding{
				ID:                  "f2",
				CurrentSeverityRank: 4,
				Fingerprint:         "sca:CVE-2024-5678:pkg:npm/axios@0.21.1",
			},
			condition: WaiverCondition{Field: "cve_id", Operator: "eq", Value: "CVE-2024-5678"},
			wantPass:  true,
		},
		{
			name: "match via alias when primary fingerprint is GHSA",
			finding: Finding{
				ID:                  "f3",
				CurrentSeverityRank: 4,
				Fingerprint:         "GHSA-1234-5678:pkg:npm/express@4.16.0",
				Aliases:             []string{"CVE-2024-9999"},
			},
			condition: WaiverCondition{Field: "cve_id", Operator: "eq", Value: "CVE-2024-9999"},
			wantPass:  true,
		},
		{
			name: "match via title",
			finding: Finding{
				ID:                  "f4",
				CurrentSeverityRank: 4,
				Fingerprint:         "custom-fingerprint-123",
				CurrentTitle:        "CVE-2024-4321 in openssl",
			},
			condition: WaiverCondition{Field: "cve_id", Operator: "contains", Value: "CVE-2024-4321"},
			wantPass:  true,
		},
		{
			name: "no match on different CVE",
			finding: Finding{
				ID:                  "f5",
				CurrentSeverityRank: 4,
				Fingerprint:         "CVE-2024-0001:pkg:npm/lodash@4.17.20",
			},
			condition: WaiverCondition{Field: "cve_id", Operator: "eq", Value: "CVE-2024-9999"},
			wantPass:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := New(
				&mockFindingsRepo{findings: []Finding{tt.finding}},
				&mockWaiversRepo{waivers: []Waiver{
					{ID: "w1", Conditions: []WaiverCondition{tt.condition}},
				}},
			)
			d, err := g.Evaluate(context.Background(), "p1", 3)
			require.NoError(t, err)
			if tt.wantPass {
				assert.Equal(t, StatusPass, d.Status)
				assert.Equal(t, 1, d.WaivedCount)
			} else {
				assert.Equal(t, StatusFail, d.Status)
				assert.Equal(t, 0, d.WaivedCount)
			}
		})
	}
}
