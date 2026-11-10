package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

const gateCommit = "9f8e7d6c5b4a39281706f5e4d3c2b1a098765432"

func gateCommitFinding(id, kind string) port.Finding {
	return port.Finding{
		ID: id, ProjectID: makeProject(true).ID, FindingKind: kind, Fingerprint: "fp-" + id,
		CurrentTitle: "finding " + id, CurrentSeverity: "high", CurrentSeverityRank: 4,
		State: "open", AnalysisState: "unanalyzed",
	}
}

// TestGetIntroducedCommitGateStatus_JoinsEveryScanner pins the point of the
// commit scope: findings that different scanners introduced at one commit
// block together, and open findings the commit did not introduce stay out.
func TestGetIntroducedCommitGateStatus_JoinsEveryScanner(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(context.Context, string) (port.Project, error) { return makeProject(true), nil }
	var askedCommit string
	rr.hasCommitFn = func(_ context.Context, _, commit string) (bool, error) {
		askedCommit = commit
		return true, nil
	}
	trivy := gateCommitFinding("00000000-0000-0000-0000-000000000031", "sca")
	semgrep := gateCommitFinding("00000000-0000-0000-0000-000000000032", "sast")
	debt := gateCommitFinding("00000000-0000-0000-0000-000000000033", "sca")
	var introducedFor string
	fr.listFindingsIntroducedByCommitFn = func(_ context.Context, _, commit string) ([]port.Finding, error) {
		introducedFor = commit
		return []port.Finding{trivy, semgrep}, nil
	}
	fr.listGateCandidatesFn = func(context.Context, string, int16) ([]port.GateCandidate, error) {
		return []port.GateCandidate{{Finding: trivy}, {Finding: semgrep}, {Finding: debt}}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Reports: rr, Findings: fr, Waivers: &mockWaiverRepo{}}})

	out, err := uc.GetIntroducedCommitGateStatus(adminCtx(), "my-app", 0, " 9F8E7D6C5B4A39281706F5E4D3C2B1A098765432 ")
	require.NoError(t, err)
	assert.Equal(t, gateCommit, askedCommit, "the commit is matched the way ingest stored it")
	assert.Equal(t, gateCommit, introducedFor)
	assert.True(t, out.ThresholdBreached)
	assert.EqualValues(t, 2, out.BlockingCount)
	assert.ElementsMatch(t, []string{trivy.ID, semgrep.ID}, out.BlockedBy)
	assert.False(t, out.ReportOnly, "enforce mode is the default")
}

// TestGetIntroducedCommitGateStatus_NoCompletedScan pins that a commit nobody
// finished scanning has no verdict: it must not read as a pass.
func TestGetIntroducedCommitGateStatus_NoCompletedScan(t *testing.T) {
	for name, commit := range map[string]string{"unscanned commit": gateCommit, "blank commit": "  "} {
		t.Run(name, func(t *testing.T) {
			pr, rr, fr := makeTestRepos()
			pr.getBySlugFn = func(context.Context, string) (port.Project, error) { return makeProject(true), nil }
			rr.hasCommitFn = func(context.Context, string, string) (bool, error) { return false, nil }
			fr.listFindingsIntroducedByCommitFn = func(context.Context, string, string) ([]port.Finding, error) {
				t.Fatal("an unscanned commit must not be evaluated")
				return nil, nil
			}
			uc := New(Deps{Stores: &port.Stores{Projects: pr, Reports: rr, Findings: fr, Waivers: &mockWaiverRepo{}}})

			_, err := uc.GetIntroducedCommitGateStatus(adminCtx(), "my-app", 0, commit)
			require.ErrorIs(t, err, ErrNoReportForCommit)
		})
	}
}
