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
