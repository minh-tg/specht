package gate

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEvaluateIntroducedOnly_FiltersByReport(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0001", IntroducedByReportID: "r1"},
			{ID: "f2", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0002", IntroducedByReportID: "r2"},
		}},
		&mockWaiversRepo{},
	)
	d, err := g.EvaluateIntroducedOnly(context.Background(), "proj-1", 3, "r1", nil)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, d.Status)
	assert.Equal(t, []string{"f1"}, d.BlockedBy)
	assert.Equal(t, 1, d.TotalBlocking)
}

func TestEvaluateIntroducedOnly_WaiversApply(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0001", IntroducedByReportID: "r1"},
		}},
		&mockWaiversRepo{waivers: []Waiver{
			{ID: "w1", Targets: []WaiverTarget{{FindingID: "f1"}}},
		}},
	)
	d, err := g.EvaluateIntroducedOnly(context.Background(), "proj-1", 3, "r1", nil)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, d.Status)
	assert.Equal(t, 1, d.WaivedCount)
	assert.Equal(t, 1, d.TotalBlocking)
}

func TestEvaluateIntroducedOnly_NoMatch_Pass(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0001", IntroducedByReportID: "r1"},
		}},
		&mockWaiversRepo{},
	)
	d, err := g.EvaluateIntroducedOnly(context.Background(), "proj-1", 3, "r9", nil)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, d.Status)
	assert.Empty(t, d.BlockedBy)
	assert.Equal(t, 0, d.TotalBlocking)
}

func TestEvaluateIntroducedAtCommit_FiltersByCommit(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0001", IntroducedCommitSha: "abc123"},
			{ID: "f2", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0002", IntroducedCommitSha: "older"},
			{ID: "f3", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0003"},
		}},
		&mockWaiversRepo{},
	)
	d, err := g.EvaluateIntroducedAtCommit(context.Background(), "proj-1", 3, "abc123", nil)
	require.NoError(t, err)
	assert.Equal(t, StatusFail, d.Status)
	assert.Equal(t, []string{"f1"}, d.BlockedBy)
	assert.Equal(t, 1, d.TotalBlocking)
}

func TestEvaluateIntroducedOnly_EmptyReportMatchesNothing(t *testing.T) {
	g := New(
		&mockFindingsRepo{findings: []Finding{
			{ID: "f1", CurrentSeverityRank: 4, Fingerprint: "CVE-2024-0001"},
		}},
		&mockWaiversRepo{},
	)
	d, err := g.EvaluateIntroducedOnly(context.Background(), "proj-1", 3, "", nil)
	require.NoError(t, err)
	assert.Equal(t, StatusPass, d.Status, "empty scope must match nothing, not unattributed findings")
	assert.Equal(t, 0, d.TotalBlocking)
}
