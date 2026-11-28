package usecase

import (
	"context"
	"slices"
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
// can see that a project the caller cannot reach never reaches the store. It filters and counts the
// way the SQL does. totals overrides the reported total of a kind, for rows beyond those listed.
type nyStore struct {
	port.NeedsYouStore
	managed  []string
	pending  []port.NeedsYouWaiver
	decided  []port.NeedsYouWaiver
	ending   []port.NeedsYouWaiver
	assigned []port.NeedsYouFinding
	totals   map[string]int

	pendingFor, endingFor, assignedFor, hideOwnIn []string
	limits                                        map[string]int32
}

func (s *nyStore) total(kind string, listed int) int {
	if n, ok := s.totals[kind]; ok {
		return n
	}
	return listed
}

func (s *nyStore) asked(kind string, limit int32) {
	if s.limits == nil {
		s.limits = map[string]int32{}
	}
	s.limits[kind] = limit
}

func (s *nyStore) ListManagedProjectIDs(context.Context, string) ([]string, error) {
	return s.managed, nil
}

func (s *nyStore) ListProjectsWithOwnPendingRequests(_ context.Context, userID string, ids []string) ([]string, error) {
	var out []string
	for _, w := range s.pending {
		if w.RequestedBy == userID && slices.Contains(ids, w.ProjectID) && !slices.Contains(out, w.ProjectID) {
			out = append(out, w.ProjectID)
		}
	}
	return out, nil
}

func (s *nyStore) ListPendingWaiverRequests(_ context.Context, callerID string, ids, hideOwnIn []string, limit int32) (port.NeedsYouWaivers, error) {
	s.pendingFor, s.hideOwnIn = ids, hideOwnIn
	s.asked(NeedsYouWaiverToDecide, limit)
	var out port.NeedsYouWaivers
	for _, w := range s.pending {
		if w.RequestedBy != callerID || !slices.Contains(hideOwnIn, w.ProjectID) {
			out.Items = append(out.Items, w)
		}
	}
	out.Total = s.total(NeedsYouWaiverToDecide, len(out.Items))
	return out, nil
}

func (s *nyStore) ListDecidedWaiverRequests(_ context.Context, _ string, _ []string, _, freshSince time.Time, limit int32) (port.NeedsYouWaivers, error) {
	s.asked(NeedsYouRequestDecided, limit)
	out := port.NeedsYouWaivers{Items: s.decided, Total: s.total(NeedsYouRequestDecided, len(s.decided))}
	for _, w := range s.decided {
		if !w.At.Before(freshSince) {
			out.Fresh++
		}
	}
	return out, nil
}

func (s *nyStore) ListWaiversEnding(_ context.Context, ids []string, _, _ time.Time, limit int32) (port.NeedsYouWaivers, error) {
	s.endingFor = ids
	s.asked(NeedsYouWaiverEnding, limit)
	return port.NeedsYouWaivers{Items: s.ending, Total: s.total(NeedsYouWaiverEnding, len(s.ending))}, nil
}

func (s *nyStore) ListOpenFindingsAssignedTo(_ context.Context, _ string, ids []string, limit int32) (port.NeedsYouFindings, error) {
	s.assignedFor = ids
	s.asked(NeedsYouFindingAssigned, limit)
	return port.NeedsYouFindings{Items: s.assigned, Total: s.total(NeedsYouFindingAssigned, len(s.assigned))}, nil
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
			assert.Equal(t, tc.want, out.Totals.WaiverToDecide, "the store leaves the hidden request out of the total too")
			assert.Equal(t, tc.want, out.Count)
		})
	}
}

// A global admin may approve their own request whoever else can decide it, as checkSelfApproval
// allows, so it waits on them like anyone else's.
func TestGetNeedsYou_AGlobalAdminDecidesTheirOwnRequest(t *testing.T) {
	store := &nyStore{pending: []port.NeedsYouWaiver{nyWaiver("own", nyProjA, nyAlice, nyNow.Add(-time.Hour))}}
	out, err := nyUsecase(store, 1).GetNeedsYou(nyCtx(nyAlice, auth.RoleAdmin))

	require.NoError(t, err)
	assert.Empty(t, store.hideOwnIn)
	assert.Equal(t, []string{NeedsYouWaiverToDecide}, kinds(out.Items))
	assert.Equal(t, 1, out.Count)
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
		{ID: "lapsed", ProjectSlug: "alpha", Name: "Waiver request: lapsed", Status: "rejected", DecisionReason: "expired", DecisionNote: "expired before a decision", At: nyNow.Add(-2 * time.Hour)},
	}}
	out, err := nyUsecase(store, 1).GetNeedsYou(nyCtx(nyAlice, "member"))

	require.NoError(t, err)
	require.Len(t, out.Items, 3)
	assert.Equal(t, []string{"approved", "rejected", "expired"}, []string{out.Items[0].Status, out.Items[1].Status, out.Items[2].Status})
	assert.Equal(t, "too broad", out.Items[1].Detail, "a reviewer's note is kept")
	assert.Empty(t, out.Items[2].Detail, "the expiry sweep's fixed note would repeat the status")
	assert.Equal(t, 2, out.Count, "the answer from ten days ago is listed only")
}

// Ending waivers are for managers, and every kind that asks for action counts in full beyond the
// listed items, with the total of each kind in the response.
func TestGetNeedsYou_CountsEveryItemThatAsksForActionBeyondTheListed(t *testing.T) {
	store := &nyStore{
		managed:  []string{nyProjA},
		pending:  []port.NeedsYouWaiver{nyWaiver("p1", nyProjA, nyBob, nyNow.Add(-time.Hour))},
		ending:   []port.NeedsYouWaiver{{ID: "e1", ProjectSlug: "alpha", Name: "Waiver: lodash", Status: "approved", At: nyNow.Add(48 * time.Hour)}},
		assigned: []port.NeedsYouFinding{{ID: "f1", ProjectSlug: "alpha", Title: "lodash", Severity: "high", LastSeenAt: nyNow}},
		decided: []port.NeedsYouWaiver{
			{ID: "new", ProjectSlug: "alpha", Name: "new", Status: "approved", At: nyNow.Add(-time.Hour)},
			{ID: "old", ProjectSlug: "alpha", Name: "old", Status: "rejected", At: nyNow.Add(-10 * 24 * time.Hour)},
		},
		totals: map[string]int{NeedsYouWaiverToDecide: 70, NeedsYouWaiverEnding: 3, NeedsYouFindingAssigned: 120, NeedsYouRequestDecided: 9},
	}
	out, err := nyUsecase(store, 1).GetNeedsYou(nyCtx(nyAlice, "member"))

	require.NoError(t, err)
	assert.Equal(t, []string{NeedsYouWaiverToDecide, NeedsYouWaiverEnding, NeedsYouFindingAssigned, NeedsYouRequestDecided, NeedsYouRequestDecided}, kinds(out.Items))
	assert.Equal(t, "/alpha/findings/f1", out.Items[2].Link)
	assert.Equal(t, NeedsYouTotals{WaiverToDecide: 70, WaiverEnding: 3, FindingAssigned: 120, RequestDecided: 9}, out.Totals)
	assert.Equal(t, 70+3+120+1, out.Count, "every request, ending waiver and assigned finding, and the one fresh answer")
}

// Each item opens the Waivers tab that holds it: a request on Waiting, the page's default, a waiver
// that ends on In force, and an answer on In force while its waiver lets findings through and on
// Closed once it does not.
func TestGetNeedsYou_LinksEachWaiverToItsTab(t *testing.T) {
	later := nyNow.Add(48 * time.Hour)
	past := nyNow.Add(-time.Hour)
	store := &nyStore{
		managed: []string{nyProjA},
		pending: []port.NeedsYouWaiver{nyWaiver("p1", nyProjA, nyBob, nyNow.Add(-time.Hour))},
		ending:  []port.NeedsYouWaiver{{ID: "e1", ProjectSlug: "alpha", Name: "Waiver: lodash", Status: "approved", At: later}},
		decided: []port.NeedsYouWaiver{
			{ID: "on", ProjectSlug: "alpha", Name: "on", Status: "approved", Enabled: true, ExpiresAt: &later, At: nyNow},
			{ID: "open-ended", ProjectSlug: "alpha", Name: "open-ended", Status: "approved", Enabled: true, At: nyNow},
			{ID: "revoked", ProjectSlug: "alpha", Name: "revoked", Status: "approved", ExpiresAt: &later, At: nyNow},
			{ID: "ran-out", ProjectSlug: "alpha", Name: "ran-out", Status: "approved", Enabled: true, ExpiresAt: &past, At: nyNow},
			{ID: "no", ProjectSlug: "alpha", Name: "no", Status: "rejected", At: nyNow},
			{ID: "lapsed", ProjectSlug: "alpha", Name: "lapsed", Status: "rejected", DecisionReason: "expired", At: nyNow},
		},
	}
	out, err := nyUsecase(store, 1).GetNeedsYou(nyCtx(nyAlice, "member"))

	require.NoError(t, err)
	links := map[string]string{}
	for _, item := range out.Items {
		links[item.Kind+" "+item.Title] = item.Link
	}
	assert.Equal(t, map[string]string{
		"waiver_to_decide Waiver request: p1": "/alpha/waivers",
		"waiver_ending Waiver: lodash":        "/alpha/waivers?state=in_force",
		"request_decided on":                  "/alpha/waivers?state=in_force",
		"request_decided open-ended":          "/alpha/waivers?state=in_force",
		"request_decided revoked":             "/alpha/waivers?state=closed",
		"request_decided ran-out":             "/alpha/waivers?state=closed",
		"request_decided no":                  "/alpha/waivers?state=closed",
		"request_decided lapsed":              "/alpha/waivers?state=closed",
	}, links)
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

// Every kind lists at most the documented 50.
func TestGetNeedsYou_ListsAtMostFiftyOfAKind(t *testing.T) {
	store := &nyStore{managed: []string{nyProjA}}
	_, err := nyUsecase(store, 1).GetNeedsYou(nyCtx(nyAlice, "member"))

	require.NoError(t, err)
	assert.Equal(t, map[string]int32{
		NeedsYouWaiverToDecide: 50, NeedsYouWaiverEnding: 50, NeedsYouFindingAssigned: 50, NeedsYouRequestDecided: 50,
	}, store.limits)
}
