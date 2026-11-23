package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const (
	nyAlice  = "00000000-0000-0000-0000-0000000000a1"
	nyBob    = "00000000-0000-0000-0000-0000000000b2"
	nyProjA  = "00000000-0000-0000-0000-00000000aaa1"
	nyProjB  = "00000000-0000-0000-0000-00000000bbb2"
	nyHidden = "00000000-0000-0000-0000-00000000ccc3"
)

var nyNow = time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)

// nyStore answers from fixed rows and records the project ids each list was asked for, so a test
// can see that a project the caller cannot reach never reaches the store.
type nyStore struct {
	port.NeedsYouStore
	managed  []string
	pending  []port.NeedsYouWaiver
	decided  []port.NeedsYouWaiver
	ending   []port.NeedsYouWaiver
	assigned []port.NeedsYouFinding
	total    int64

	pendingFor, endingFor, assignedFor []string
}

func (s *nyStore) ListManagedProjectIDs(context.Context, string) ([]string, error) {
	return s.managed, nil
}

func (s *nyStore) ListPendingWaiverRequests(_ context.Context, ids []string, _ int32) ([]port.NeedsYouWaiver, error) {
	s.pendingFor = ids
	return s.pending, nil
}

func (s *nyStore) ListDecidedWaiverRequests(context.Context, string, []string, time.Time, int32) ([]port.NeedsYouWaiver, error) {
	return s.decided, nil
}

func (s *nyStore) ListWaiversEnding(_ context.Context, ids []string, _, _ time.Time, _ int32) ([]port.NeedsYouWaiver, error) {
	s.endingFor = ids
	return s.ending, nil
}

func (s *nyStore) ListOpenFindingsAssignedTo(_ context.Context, _ string, ids []string, _ int32) ([]port.NeedsYouFinding, error) {
	s.assignedFor = ids
	return s.assigned, nil
}

func (s *nyStore) CountOpenFindingsAssignedTo(context.Context, string, []string) (int64, error) {
	return s.total, nil
}

func nyUsecase(store *nyStore, otherDeciders int) *Usecases {
	pr := &mockProjectRepo{
		listAccessibleIDsFn: func(context.Context, string) ([]string, error) { return []string{nyProjA, nyProjB}, nil },
		listByIDsFn: func(_ context.Context, ids []string) ([]port.Project, error) {
			out := make([]port.Project, len(ids))
			for i, id := range ids {
				out[i] = port.Project{ID: id, Slug: map[string]string{nyProjA: "alpha", nyProjB: "beta"}[id]}
			}
			return out, nil
		},
		listFn: func(context.Context) ([]port.Project, error) {
			return []port.Project{{ID: nyProjA, Slug: "alpha"}, {ID: nyProjB, Slug: "beta"}, {ID: nyHidden, Slug: "hidden"}}, nil
		},
		otherDecidersFn: func(context.Context, string, string) (int, error) { return otherDeciders, nil },
	}
	return New(Deps{
		Stores: &port.Stores{Projects: pr, NeedsYou: store},
		Now:    func() time.Time { return nyNow },
	})
}

func nyCtx(userID, role string) context.Context {
	return auth.ContextWithIdentity(context.Background(), &auth.Identity{UserID: userID, Role: role})
}

func nyWaiver(id, project, requestedBy string, at time.Time) port.NeedsYouWaiver {
	return port.NeedsYouWaiver{
		ID: id, ProjectID: project, ProjectSlug: map[string]string{nyProjA: "alpha", nyProjB: "beta"}[project],
		Name: "Waiver request: " + id, Reason: "not reachable", RequestedBy: requestedBy, Status: "pending", At: at,
	}
}

func kinds(items []NeedsYouItem) []string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = item.Kind
	}
	return out
}

// A manager sees the requests of others on the projects they manage, and not the ones on a project
// where they are only a member.
func TestGetNeedsYou_AManagerDecidesOthersRequestsOnTheirProjectsOnly(t *testing.T) {
	store := &nyStore{
		managed: []string{nyProjA},
		pending: []port.NeedsYouWaiver{nyWaiver("w1", nyProjA, nyBob, nyNow.Add(-time.Hour))},
	}
	out, err := nyUsecase(store, 1).GetNeedsYou(nyCtx(nyAlice, "member"))

	require.NoError(t, err)
	assert.Equal(t, []string{nyProjA}, store.pendingFor, "only a managed project is asked for requests")
	assert.Equal(t, []string{nyProjA, nyProjB}, store.assignedFor, "assignments come from every reachable project")
	assert.Equal(t, []string{NeedsYouWaiverToDecide}, kinds(out.Items))
	assert.Equal(t, "/alpha/waivers", out.Items[0].Link)
	assert.Equal(t, "not reachable", out.Items[0].Detail)
	assert.Equal(t, 1, out.Count)
}

// A member who manages nothing is never asked to decide.
func TestGetNeedsYou_AMemberDecidesNothing(t *testing.T) {
	store := &nyStore{pending: []port.NeedsYouWaiver{nyWaiver("w1", nyProjA, nyBob, nyNow)}}
	out, err := nyUsecase(store, 1).GetNeedsYou(nyCtx(nyAlice, "member"))

	require.NoError(t, err)
	assert.Nil(t, store.pendingFor, "no project is asked for requests")
	assert.Empty(t, out.Items)
	assert.Zero(t, out.Count)
}

// The rule ApproveWaiver applies: someone's own request waits on another person, unless nobody
// else can decide it.
func TestGetNeedsYou_AnOwnRequestCountsOnlyForTheSoleDecider(t *testing.T) {
	own := nyWaiver("own", nyProjA, nyAlice, nyNow.Add(-time.Hour))
	for name, tc := range map[string]struct {
		others int
		want   int
	}{
		"another manager can decide it": {others: 1, want: 0},
		"nobody else can":               {others: 0, want: 1},
	} {
		t.Run(name, func(t *testing.T) {
			store := &nyStore{managed: []string{nyProjA}, pending: []port.NeedsYouWaiver{own}}
			out, err := nyUsecase(store, tc.others).GetNeedsYou(nyCtx(nyAlice, "member"))

			require.NoError(t, err)
			assert.Len(t, out.Items, tc.want)
			assert.Equal(t, tc.want, out.Count)
		})
	}
}

// A global admin may decide on every project, hidden from nobody.
func TestGetNeedsYou_AGlobalAdminReachesEveryProject(t *testing.T) {
	store := &nyStore{pending: []port.NeedsYouWaiver{nyWaiver("w1", nyHidden, nyBob, nyNow)}}
	_, err := nyUsecase(store, 1).GetNeedsYou(nyCtx(nyAlice, auth.RoleAdmin))

	require.NoError(t, err)
	assert.Equal(t, []string{nyProjA, nyProjB, nyHidden}, store.pendingFor)
	assert.Equal(t, []string{nyProjA, nyProjB, nyHidden}, store.endingFor)
}

// Answers stay listed for the window, and only a fresh one asks for attention in the badge.
func TestGetNeedsYou_AnOldAnswerIsListedButNotCounted(t *testing.T) {
	store := &nyStore{decided: []port.NeedsYouWaiver{
		{ID: "new", ProjectSlug: "alpha", Name: "Waiver request: new", Status: "approved", At: nyNow.Add(-time.Hour)},
		{ID: "old", ProjectSlug: "alpha", Name: "Waiver request: old", Status: "rejected", DecisionNote: "too broad", At: nyNow.Add(-10 * 24 * time.Hour)},
		{ID: "lapsed", ProjectSlug: "alpha", Name: "Waiver request: lapsed", Status: "rejected", DecisionReason: "expired", At: nyNow.Add(-2 * time.Hour)},
	}}
	out, err := nyUsecase(store, 1).GetNeedsYou(nyCtx(nyAlice, "member"))

	require.NoError(t, err)
	require.Len(t, out.Items, 3)
	assert.Equal(t, []string{"approved", "rejected", "expired"}, []string{out.Items[0].Status, out.Items[1].Status, out.Items[2].Status})
	assert.Equal(t, "too broad", out.Items[1].Detail)
	assert.Equal(t, 2, out.Count, "the answer from ten days ago is listed only")
}

// Ending waivers are for managers, and assigned findings count in full beyond the listed ones.
func TestGetNeedsYou_CountsEndingWaiversAndEveryAssignedFinding(t *testing.T) {
	store := &nyStore{
		managed:  []string{nyProjA},
		ending:   []port.NeedsYouWaiver{{ID: "e1", ProjectSlug: "alpha", Name: "Waiver: lodash", Status: "approved", At: nyNow.Add(48 * time.Hour)}},
		assigned: []port.NeedsYouFinding{{ID: "f1", ProjectSlug: "alpha", Title: "lodash", Severity: "high", LastSeenAt: nyNow}},
		total:    12,
	}
	out, err := nyUsecase(store, 1).GetNeedsYou(nyCtx(nyAlice, "member"))

	require.NoError(t, err)
	assert.Equal(t, []string{NeedsYouWaiverEnding, NeedsYouFindingAssigned}, kinds(out.Items))
	assert.Equal(t, "/alpha/findings/f1", out.Items[1].Link)
	assert.Equal(t, 12, out.AssignedFindings)
	assert.Equal(t, 13, out.Count, "one waiver ending and twelve assigned findings")
}

func TestGetNeedsYou_NothingWaitingGivesAnEmptyListNotNull(t *testing.T) {
	out, err := nyUsecase(&nyStore{}, 1).GetNeedsYou(nyCtx(nyAlice, "member"))

	require.NoError(t, err)
	assert.NotNil(t, out.Items)
	assert.Empty(t, out.Items)
	assert.Zero(t, out.Count)
}

func TestGetNeedsYou_RefusesAnAPIKeyAndAnAnonymousCaller(t *testing.T) {
	uc := nyUsecase(&nyStore{}, 1)
	key := auth.ContextWithIdentity(context.Background(), &auth.Identity{IsAPIKey: true, ProjectID: nyProjA})

	_, err := uc.GetNeedsYou(key)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
	_, err = uc.GetNeedsYou(context.Background())
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}
