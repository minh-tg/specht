package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

const (
	adaID = "00000000-0000-0000-0000-0000000000a1"
	boID  = "00000000-0000-0000-0000-0000000000a2"
	sysID = "00000000-0000-0000-0000-0000000000a3"
)

// peopleStore answers ListByIDs from a fixed set and records every call.
type peopleStore struct {
	*mockUserRepo
	calls [][]string
}

func newPeopleStore() *peopleStore {
	ps := &peopleStore{mockUserRepo: &mockUserRepo{}}
	known := []port.User{
		{ID: adaID, Email: "ada@acme.example", DisplayName: strPtr("Ada Okafor")},
		{ID: boID, Email: "bo@acme.example"},
		{ID: sysID, Email: "system@specht.local"},
	}
	ps.listByIDsFn = func(_ context.Context, ids []string) ([]port.User, error) {
		ps.calls = append(ps.calls, ids)
		var out []port.User
		for _, u := range known {
			for _, id := range ids {
				if id == u.ID {
					out = append(out, u)
				}
			}
		}
		return out, nil
	}
	return ps
}

func waiversWithPeople(project port.Project, ps *peopleStore) *Usecases {
	at := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	wr := &mockWaiverRepo{
		listFn: func(context.Context, string) ([]port.Waiver, error) {
			return []port.Waiver{
				{ID: "w1", ProjectID: project.ID, Name: "one", RequestedBy: strPtr(adaID), DecidedBy: strPtr(boID), CreatedAt: at, UpdatedAt: at},
				{ID: "w2", ProjectID: project.ID, Name: "two", RequestedBy: strPtr(adaID), CreatedAt: at, UpdatedAt: at},
				{ID: "w3", ProjectID: project.ID, Name: "three", CreatedAt: at, UpdatedAt: at},
			}, nil
		},
	}
	uc := waiverUsecaseForProject(project, wr, "")
	uc.deps.Stores.Users = ps
	return uc
}

func TestListWaivers_NamesThePeopleBehindEachOne(t *testing.T) {
	ps := newPeopleStore()
	uc := waiversWithPeople(makeProject(true), ps)

	got, err := uc.ListWaivers(adminCtx(), "my-app")

	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Equal(t, "Ada Okafor", got[0].RequestedByName, "a display name is preferred")
	assert.Equal(t, "bo@acme.example", got[0].DecidedByName, "the address stands in when there is no name")
	assert.Equal(t, "Ada Okafor", got[1].RequestedByName)
	assert.Empty(t, got[1].DecidedByName)
	assert.Empty(t, got[2].RequestedByName, "a waiver a manager created has no requester to name")
	require.Len(t, ps.calls, 1, "one lookup for the whole list, not one per waiver")
	assert.ElementsMatch(t, []string{adaID, boID}, ps.calls[0], "each person once")
}

func TestListWaivers_AnAPIKeyIsNotGivenNames(t *testing.T) {
	ps := newPeopleStore()
	project := makeProject(true)
	uc := waiversWithPeople(project, ps)

	got, err := uc.ListWaivers(apiKeyCtx("key-1", project.ID), "my-app")

	require.NoError(t, err)
	require.Len(t, got, 3)
	assert.Empty(t, got[0].RequestedByName)
	assert.Empty(t, ps.calls, "a pipeline has no use for the people behind a project")
}

func TestListWaivers_ALookupFailureDoesNotBreakTheList(t *testing.T) {
	ps := newPeopleStore()
	ps.listByIDsFn = func(context.Context, []string) ([]port.User, error) { return nil, errors.New("db down") }
	uc := waiversWithPeople(makeProject(true), ps)

	got, err := uc.ListWaivers(adminCtx(), "my-app")

	require.NoError(t, err, "names are a convenience")
	require.Len(t, got, 3)
	assert.Empty(t, got[0].RequestedByName)
	assert.Equal(t, "one", got[0].Name)
}

func TestListWaivers_ASetupWithoutAUserStoreStillWorks(t *testing.T) {
	uc := waiversWithPeople(makeProject(true), newPeopleStore())
	uc.deps.Stores.Users = nil

	got, err := uc.ListWaivers(adminCtx(), "my-app")

	require.NoError(t, err)
	assert.Len(t, got, 3)
}

func TestPeopleLabels_TheSystemAccountReadsAsSystem(t *testing.T) {
	ps := newPeopleStore()
	uc := New(Deps{Stores: &port.Stores{Users: ps}})

	labels := uc.peopleLabels(adminCtx(), []string{sysID, adaID, "", sysID})

	assert.Equal(t, "System", labels[sysID], "automated actions are not attributed to a mailbox")
	assert.Equal(t, "Ada Okafor", labels[adaID])
	assert.NotContains(t, labels, "")
	require.Len(t, ps.calls, 1)
	assert.ElementsMatch(t, []string{sysID, adaID}, ps.calls[0], "blanks and repeats are dropped")
}

func TestPeopleLabels_NothingToLookUpMeansNoQuery(t *testing.T) {
	ps := newPeopleStore()
	uc := New(Deps{Stores: &port.Stores{Users: ps}})

	assert.Empty(t, uc.peopleLabels(adminCtx(), nil))
	assert.Empty(t, uc.peopleLabels(adminCtx(), []string{"", ""}))
	assert.Empty(t, ps.calls)
}

func TestListWaiverEvents_NamesTheActor(t *testing.T) {
	project := makeProject(true)
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	at := time.Date(2025, 4, 5, 6, 7, 8, 0, time.UTC)
	wr := &mockWaiverRepo{
		getByIDFn: func(_ context.Context, id, projectID string) (port.Waiver, error) {
			return port.Waiver{ID: id, ProjectID: projectID}, nil
		},
		listEventsFn: func(_ context.Context, id string) ([]port.WaiverEvent, error) {
			return []port.WaiverEvent{
				{ID: "e1", WaiverID: id, EventType: "approved", ActorID: boID, CreatedAt: at},
				{ID: "e2", WaiverID: id, EventType: "auto_disabled", CreatedAt: at},
			}, nil
		},
	}
	ps := newPeopleStore()
	uc := waiverUsecaseForProject(project, wr, "")
	uc.deps.Stores.Users = ps

	got, err := uc.ListWaiverEvents(adminCtx(), "my-app", waiverID)

	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "bo@acme.example", got[0].ActorName)
	assert.Empty(t, got[1].ActorName, "an event with no actor, such as an expiry, names nobody")
}

func TestGetFindingEvents_NamesWhoDidIt(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(context.Context, string) (port.Finding, error) { return makeFindingRow(1), nil }
	fr.listEventsFn = func(context.Context, string, []string, int32, int32) ([]port.FindingEvent, error) {
		return []port.FindingEvent{
			{EventType: "analysis_changed", UserID: strPtr(adaID)},
			{EventType: "created"},
		}, nil
	}
	ps := newPeopleStore()
	uc := New(Deps{Stores: &port.Stores{Findings: fr, Projects: memberProjects(), Users: ps}})

	events, err := uc.GetFindingEvents(findingScopeCtx(findingFixtureProjectID), "00000000-0000-0000-0000-000000000021", nil, 10, 0)

	require.NoError(t, err)
	require.Len(t, events, 2)
	assert.Equal(t, "Ada Okafor", events[0].UserName)
	assert.Empty(t, events[1].UserName)
}

func TestGetWaiver_NamesThePeopleOnTheDetailToo(t *testing.T) {
	project := makeProject(true)
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	wr := &mockWaiverRepo{
		getByIDFn: func(_ context.Context, id, projectID string) (port.Waiver, error) {
			return port.Waiver{ID: id, ProjectID: projectID, RequestedBy: strPtr(adaID), DecidedBy: strPtr(boID)}, nil
		},
		listConditionsFn:     func(context.Context, string) ([]port.WaiverCondition, error) { return nil, nil },
		listContextsFn:       func(context.Context, string) ([]port.WaiverContext, error) { return nil, nil },
		listFindingTargetsFn: func(context.Context, string) ([]port.WaiverFindingTarget, error) { return nil, nil },
	}
	ps := newPeopleStore()
	uc := waiverUsecaseForProject(project, wr, "")
	uc.deps.Stores.Users = ps

	got, err := uc.GetWaiver(adminCtx(), "my-app", waiverID)

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "Ada Okafor", got.RequestedByName, "names reach the response, not a copy of it")
	assert.Equal(t, "bo@acme.example", got.DecidedByName)
}
