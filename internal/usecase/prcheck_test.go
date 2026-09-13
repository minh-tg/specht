package usecase

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/provider"
)

const prcheckCommit = "abc123abc123abc123abc123abc123abc123abc1"

// prcheckHarness builds a preview stack: f1 introduced at prcheckCommit
// with a mappable code location, f2 introduced earlier without one.
func prcheckHarness(t *testing.T) (*Usecases, *mockFindingRepo) {
	t.Helper()
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	commit := prcheckCommit
	older := "older000older000older000older000older000older0"
	f1 := port.Finding{
		ID: "00000000-0000-0000-0000-000000000021", ProjectID: makeProject(true).ID,
		FindingKind: "sast", Fingerprint: "fp1", CurrentTitle: "XSS in handler",
		CurrentSeverity: "high", CurrentSeverityRank: 4,
		State: "open", IntroducedCommitSha: &commit,
	}
	f2 := port.Finding{
		ID: "00000000-0000-0000-0000-000000000022", ProjectID: makeProject(true).ID,
		FindingKind: "sast", Fingerprint: "fp2", CurrentTitle: "Old debt",
		CurrentSeverity: "medium", CurrentSeverityRank: 2,
		State: "open", IntroducedCommitSha: &older,
	}
	fr.listByProjectFn = func(ctx context.Context, projectID string, severities, states, kinds, environments, targets []string, limit, offset int32) ([]port.Finding, error) {
		return []port.Finding{f1, f2}, nil
	}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		if id == f1.ID {
			return f1, nil
		}
		return f2, nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		if findingID == f1.ID {
			return port.FindingDisplayContext{
				ToolName: "semgrep",
				Metadata: json.RawMessage(`{"specht":{"code_location":{"File":"app/main.go","StartLine":10,"EndLine":12}}}`),
			}, nil
		}
		return port.FindingDisplayContext{ToolName: "semgrep"}, nil
	}
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minRank int16) ([]port.GateCandidate, error) {
		return []port.GateCandidate{
			{Finding: f1},
			{Finding: f2},
		}, nil
	}

	reg := provider.NewRegistry()
	require.NoError(t, reg.Register(provider.NewGitHubProvider()))
	uc := New(Deps{
		Stores: &port.Stores{
			Projects: pr, Reports: rr, Findings: fr,
			Waivers: &mockWaiverRepo{},
		},
		Providers: reg,
	})
	return uc, fr
}

func TestPreviewPRCheck_FailureWithAnnotation(t *testing.T) {
	uc, _ := prcheckHarness(t)
	ctx := findingScopeCtx(makeProject(true).ID)

	out, err := uc.PreviewPRCheck(ctx, PRCheckPreviewInput{
		ProjectSlug: "my-app",
		CommitSha:   prcheckCommit,
	})
	require.NoError(t, err)
	assert.Equal(t, "failure", out.Conclusion)
	assert.Equal(t, prcheckCommit, out.CommitSha)
	require.Len(t, out.Annotations, 1)
	a := out.Annotations[0]
	assert.Equal(t, "app/main.go", a.File)
	assert.Equal(t, 10, a.StartLine)
	assert.Equal(t, 12, a.EndLine)
	assert.Contains(t, a.Message, "introduced by this change")
	assert.Equal(t, 1, out.SummaryCounts["high"], "summary covers considered findings")
	assert.Equal(t, "github", out.Provider)
}

func TestPreviewPRCheck_WaivedIntroducedPasses(t *testing.T) {
	uc, _ := prcheckHarness(t)
	uc.deps.Stores.Waivers = &mockWaiverRepo{
		listActiveFn: func(ctx context.Context, projectID string) ([]port.Waiver, error) {
			return []port.Waiver{{ID: "w1"}}, nil
		},
	}
	ctx := findingScopeCtx(makeProject(true).ID)

	out, err := uc.PreviewPRCheck(ctx, PRCheckPreviewInput{
		ProjectSlug: "my-app",
		CommitSha:   prcheckCommit,
	})
	require.NoError(t, err)
	assert.Equal(t, "success", out.Conclusion)
	assert.Empty(t, out.Annotations)
	assert.Equal(t, 1, out.WaivedCount)
}

func TestPreviewPRCheck_RequiresCommit(t *testing.T) {
	uc, _ := prcheckHarness(t)
	_, err := uc.PreviewPRCheck(context.Background(), PRCheckPreviewInput{ProjectSlug: "my-app"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "commit_sha")
}

func TestPreviewPRCheck_UnknownProvider(t *testing.T) {
	uc, _ := prcheckHarness(t)
	_, err := uc.PreviewPRCheck(context.Background(), PRCheckPreviewInput{
		ProjectSlug: "my-app", Provider: "bitkeeper", CommitSha: prcheckCommit,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown provider")
}

func TestPreviewPRCheck_ReportScope(t *testing.T) {
	uc, fr := prcheckHarness(t)
	reportID := "11111111-1111-1111-1111-111111111111"
	commit := prcheckCommit
	fr.listIntroducedByFn = func(ctx context.Context, projectID, rid string) ([]port.Finding, error) {
		assert.Equal(t, reportID, rid)
		return []port.Finding{{
			ID: "00000000-0000-0000-0000-000000000021", ProjectID: makeProject(true).ID,
			FindingKind: "sast", Fingerprint: "fp1", CurrentTitle: "XSS in handler",
			CurrentSeverity: "high", CurrentSeverityRank: 4,
			State: "open", IntroducedCommitSha: &commit,
		}}, nil
	}
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minRank int16) ([]port.GateCandidate, error) {
		return []port.GateCandidate{{
			Finding: port.Finding{
				ID: "00000000-0000-0000-0000-000000000021", ProjectID: makeProject(true).ID,
				FindingKind: "sast", Fingerprint: "fp1", CurrentTitle: "XSS in handler",
				CurrentSeverityRank: 4, AnalysisState: "unanalyzed",
				IntroducedByReportID: &reportID, IntroducedCommitSha: &commit,
			},
		}}, nil
	}
	ctx := findingScopeCtx(makeProject(true).ID)

	out, err := uc.PreviewPRCheck(ctx, PRCheckPreviewInput{
		ProjectSlug: "my-app", CommitSha: prcheckCommit, ReportID: reportID,
	})
	require.NoError(t, err)
	assert.Equal(t, "failure", out.Conclusion)
	assert.Equal(t, reportID, out.ReportID)
	require.Len(t, out.Annotations, 1)
	assert.Equal(t, reportID+":fp1", out.Annotations[0].ExternalID, "exact-scan tie keeps rerun updates stable")
}
