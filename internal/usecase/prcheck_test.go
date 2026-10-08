package usecase

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/provider"
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
	rr.getByIDFn = func(ctx context.Context, id string) (port.Report, error) {
		branch, sha := "main", prcheckCommit
		return port.Report{
			ID: id, ProjectID: makeProject(true).ID,
			ToolName: "semgrep", Status: "completed",
			Branch: &branch, CommitSha: &sha,
		}, nil
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
	fr.listByProjectFn = func(ctx context.Context, projectID string, params port.ListFindingsParams) ([]port.Finding, error) {
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
	_, err := uc.PreviewPRCheck(adminCtx(), PRCheckPreviewInput{
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

func TestPreviewPRCheck_ReportCommitMismatch(t *testing.T) {
	uc, _ := prcheckHarness(t)
	ctx := findingScopeCtx(makeProject(true).ID)

	_, err := uc.PreviewPRCheck(ctx, PRCheckPreviewInput{
		ProjectSlug: "my-app", CommitSha: "different000different000different00000",
		ReportID: "11111111-1111-1111-1111-111111111111",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not")
}

func TestPreviewPRCheck_MissingReport(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	rr.getByIDFn = func(ctx context.Context, id string) (port.Report, error) {
		return port.Report{}, port.ErrNotFound
	}
	uc := New(Deps{Stores: &port.Stores{
		Projects: pr, Reports: rr, Findings: fr, Waivers: &mockWaiverRepo{},
	}})

	_, err := uc.PreviewPRCheck(findingScopeCtx(makeProject(true).ID), PRCheckPreviewInput{
		ProjectSlug: "my-app", CommitSha: prcheckCommit,
		ReportID: "33333333-3333-3333-3333-333333333333",
	})
	require.Error(t, err, "a bogus report must fail, not plan a vacuous success")
}

func TestPreviewPRCheck_ForeignReportDenied(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	rr.getByIDFn = func(ctx context.Context, id string) (port.Report, error) {
		return port.Report{ID: id, ProjectID: "99999999-9999-9999-9999-999999999999"}, nil
	}
	uc := New(Deps{Stores: &port.Stores{
		Projects: pr, Reports: rr, Findings: fr, Waivers: &mockWaiverRepo{},
	}})

	_, err := uc.PreviewPRCheck(findingScopeCtx(makeProject(true).ID), PRCheckPreviewInput{
		ProjectSlug: "my-app", CommitSha: prcheckCommit,
		ReportID: "44444444-4444-4444-4444-444444444444",
	})
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestPreviewPRCheck_PaginatesLargeProjects(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	commit := prcheckCommit
	target := port.Finding{
		ID: "00000000-0000-0000-0000-000000000021", ProjectID: makeProject(true).ID,
		FindingKind: "sast", Fingerprint: "fp-target", CurrentTitle: "Deep cut",
		CurrentSeverity: "high", CurrentSeverityRank: 4,
		State: "open", IntroducedCommitSha: &commit,
	}
	fr.listByProjectFn = func(ctx context.Context, projectID string, params port.ListFindingsParams) ([]port.Finding, error) {
		if params.Offset == 0 {
			page := make([]port.Finding, 0, params.Limit)
			for i := int32(0); i < params.Limit; i++ {
				page = append(page, port.Finding{ID: "pad", ProjectID: projectID})
			}
			return page, nil
		}
		return []port.Finding{target}, nil
	}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return target, nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{ToolName: "semgrep"}, nil
	}
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minRank int16) ([]port.GateCandidate, error) {
		return []port.GateCandidate{{Finding: target}}, nil
	}
	uc := New(Deps{Stores: &port.Stores{
		Projects: pr, Reports: rr, Findings: fr, Waivers: &mockWaiverRepo{},
	}})

	out, err := uc.PreviewPRCheck(findingScopeCtx(makeProject(true).ID), PRCheckPreviewInput{
		ProjectSlug: "my-app", CommitSha: prcheckCommit,
	})
	require.NoError(t, err)
	assert.Equal(t, "failure", out.Conclusion, "findings past the first page must not be silently dropped")
}

func TestPreviewPRCheck_CommitCaseInsensitive(t *testing.T) {
	uc, _ := prcheckHarness(t)
	ctx := findingScopeCtx(makeProject(true).ID)

	out, err := uc.PreviewPRCheck(ctx, PRCheckPreviewInput{
		ProjectSlug: "my-app", CommitSha: "ABC123ABC123ABC123ABC123ABC123ABC123ABC1",
	})
	require.NoError(t, err)
	assert.Equal(t, "failure", out.Conclusion, "SHA case must not change the verdict")
}

func TestPreviewPRCheck_BatchedDisplayContexts(t *testing.T) {
	uc, fr := prcheckHarness(t)
	ctx := findingScopeCtx(makeProject(true).ID)

	f1ID := "00000000-0000-0000-0000-000000000021"
	batchCalled := false
	fr.listFindingDisplayContextsByIDsFn = func(ctx context.Context, ids []string) ([]port.FindingDisplayContext, error) {
		batchCalled = true
		assert.Contains(t, ids, f1ID)
		return []port.FindingDisplayContext{
			{
				FindingID: f1ID,
				ToolName:  "semgrep",
				Metadata:  json.RawMessage(`{"specht":{"code_location":{"File":"batch/main.go","StartLine":20,"EndLine":25}}}`),
			},
		}, nil
	}

	getByIDCalled := false
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		getByIDCalled = true
		return port.Finding{}, nil
	}

	out, err := uc.PreviewPRCheck(ctx, PRCheckPreviewInput{
		ProjectSlug: "my-app",
		CommitSha:   prcheckCommit,
	})
	require.NoError(t, err)
	assert.True(t, batchCalled, "ListFindingDisplayContextsByIDs must be called in batch")
	assert.False(t, getByIDCalled, "GetFinding/GetByID must not be called in a loop")
	require.Len(t, out.Annotations, 1)
	assert.Equal(t, "batch/main.go", out.Annotations[0].File)
	assert.Equal(t, 20, out.Annotations[0].StartLine)
	assert.Equal(t, 25, out.Annotations[0].EndLine)
}
