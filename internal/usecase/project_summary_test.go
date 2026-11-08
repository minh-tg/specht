package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

var (
	summaryOwn   = port.Project{ID: "00000000-0000-0000-0000-0000000000a1", Slug: "own-app", Name: "Own App"}
	summaryOther = port.Project{ID: "00000000-0000-0000-0000-0000000000b2", Slug: "other-app", Name: "Other App"}
)

// summaryUsecase serves two projects. The session user "member-1" belongs to
// summaryOwn only. Every project reports the same findings, so a row's values
// depend on the code path, not on which project it is.
func summaryUsecase(t *testing.T) *Usecases {
	t.Helper()
	projects := []port.Project{summaryOwn, summaryOther}
	pr := &mockProjectRepo{
		listFn: func(context.Context) ([]port.Project, error) { return projects, nil },
		getBySlugFn: func(_ context.Context, slug string) (port.Project, error) {
			for _, p := range projects {
				if p.Slug == slug {
					return p, nil
				}
			}
			return port.Project{}, port.ErrNotFound
		},
		getByIDFn: func(_ context.Context, id string) (port.Project, error) {
			for _, p := range projects {
				if p.ID == id {
					return p, nil
				}
			}
			return port.Project{}, port.ErrNotFound
		},
		listAccessibleIDsFn: func(_ context.Context, userID string) ([]string, error) {
			if userID == "member-1" {
				return []string{summaryOwn.ID}, nil
			}
			return nil, nil
		},
		effectiveRoleFn: func(_ context.Context, projectID, userID string) (string, error) {
			if userID == "member-1" && projectID == summaryOwn.ID {
				return auth.RoleMember, nil
			}
			return "", port.ErrNotFound
		},
	}
	store := &mockStatsStore{
		severity: []port.SeverityStat{
			{Severity: "low", Rank: 1, Count: 4},
			{Severity: "critical", Rank: 4, Count: 2},
		},
		analysis: []port.AnalysisStateStat{{State: "unanalyzed", Count: 6}},
		pending:  2,
	}
	rows := &gateRows{candidates: []port.GateCandidate{blocker("c1", 4), blocker("c2", 4), blocker("l1", 1)}}
	fr := &mockFindingRepo{listGateCandidatesFn: rows.list}
	return New(Deps{Stores: &port.Stores{Projects: pr, Stats: store, Findings: fr, Waivers: &mockWaiverRepo{}}})
}

func summarySlugs(summaries []ProjectSummary) []string {
	slugs := make([]string, len(summaries))
	for i, s := range summaries {
		slugs[i] = s.Slug
	}
	return slugs
}

func TestListProjectSummaries_MemberSeesOnlyOwnProjects(t *testing.T) {
	summaries, err := summaryUsecase(t).ListProjectSummaries(sessionCtx("member-1", auth.RoleMember))
	require.NoError(t, err)
	assert.Equal(t, []string{"own-app"}, summarySlugs(summaries))
}

func TestListProjectSummaries_OutsiderGetsEmptyList(t *testing.T) {
	summaries, err := summaryUsecase(t).ListProjectSummaries(sessionCtx("stranger", auth.RoleMember))
	require.NoError(t, err)
	assert.NotNil(t, summaries, "an empty list, not null")
	assert.Empty(t, summaries)
}

func TestListProjectSummaries_AdminSeesEveryProject(t *testing.T) {
	summaries, err := summaryUsecase(t).ListProjectSummaries(adminCtx())
	require.NoError(t, err)
	assert.Equal(t, []string{"own-app", "other-app"}, summarySlugs(summaries))
}

func TestListProjectSummaries_APIKeyNeedsReadScope(t *testing.T) {
	uc := summaryUsecase(t)

	ingestOnly := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "key-1", ProjectID: summaryOwn.ID, IsAPIKey: true, Scopes: []string{auth.ScopeIngest},
	})
	_, err := uc.ListProjectSummaries(ingestOnly)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	summaries, err := uc.ListProjectSummaries(apiKeyCtx("key-1", summaryOwn.ID))
	require.NoError(t, err)
	assert.Equal(t, []string{"own-app"}, summarySlugs(summaries), "a read key sees its own project only")
}

func TestListProjectSummaries_NoIdentityDenied(t *testing.T) {
	_, err := summaryUsecase(t).ListProjectSummaries(context.Background())
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

// The row must hold exactly what the two per-project endpoints answer, for an
// admin and for a member, so the UI can seed their caches from it.
func TestListProjectSummaries_MatchesPerProjectEndpoints(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"admin":  adminCtx(),
		"member": sessionCtx("member-1", auth.RoleMember),
	} {
		t.Run(name, func(t *testing.T) {
			uc := summaryUsecase(t)
			summaries, err := uc.ListProjectSummaries(ctx)
			require.NoError(t, err)
			require.NotEmpty(t, summaries)
			row := summaries[0]
			require.Equal(t, "own-app", row.Slug)

			wantGate, err := uc.GetBranchGateStatus(ctx, row.Slug, 0, "")
			require.NoError(t, err)
			wantStats, err := uc.GetProjectStats(ctx, row.Slug)
			require.NoError(t, err)

			assert.Equal(t, wantGate, row.Gate)
			assert.Equal(t, wantStats, row.Stats)
			assert.Equal(t, int64(2), row.Gate.BlockingCount, "the two criticals block, the low one is under the floor")
			assert.Equal(t, int32(2), row.Stats.BlockingCount)
		})
	}
}

func TestListProjectSummaries_GateFailureIsAnError(t *testing.T) {
	pr := &mockProjectRepo{listFn: func(context.Context) ([]port.Project, error) { return []port.Project{summaryOwn}, nil }}
	fr := &mockFindingRepo{listGateCandidatesFn: (&gateRows{err: errors.New("boom")}).list}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Stats: &mockStatsStore{}, Findings: fr, Waivers: &mockWaiverRepo{}}})
	_, err := uc.ListProjectSummaries(adminCtx())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "own-app")
}
