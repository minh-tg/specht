package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCheckWaiverMatchDeps builds the store fakes a CheckWaiverMatch test needs
// and returns them wired to a usecase. Project/finding IDs are fixed so
// fixtures only set the fields that matter to matching.
func testCheckWaiverMatchDeps(t *testing.T) (*mockProjectRepo, *mockFindingRepo, *mockWaiverRepo, *Usecases) {
	t.Helper()
	pr := &mockProjectRepo{}
	fr := &mockFindingRepo{}
	wr := &mockWaiverRepo{}

	project := makeProject(true)
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return project, nil
	}

	findingID := "00000000-0000-0000-0000-0000000000a1"
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return port.Finding{ID: findingID, ProjectID: project.ID, FindingKind: "sca", CurrentSeverityRank: 3}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, Findings: fr, Waivers: wr},
	})
	return pr, fr, wr, uc
}

func TestToggleWaiverUsesAtomicAuditStoreOperation(t *testing.T) {
	project := makeProject(true)
	projectID := project.ID
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	const actorID = "00000000-0000-0000-0000-000000000040"

	pr := &mockProjectRepo{
		getBySlugFn: func(context.Context, string) (port.Project, error) {
			return project, nil
		},
	}
	wr := &mockWaiverRepo{
		toggleWithEventFn: func(_ context.Context, id, gotProjectID, gotActorID string) (port.Waiver, error) {
			assert.Equal(t, waiverID, id)
			assert.Equal(t, projectID, gotProjectID)
			assert.Equal(t, actorID, gotActorID)
			return port.Waiver{ID: id, ProjectID: gotProjectID, Name: "test-waiver", Enabled: false}, nil
		},
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Waivers: wr}})

	resp, err := uc.ToggleWaiver(sessionCtx("admin", auth.RoleAdmin), "my-app", waiverID, actorID)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, waiverID, resp.ID)
	assert.False(t, resp.Enabled)
}

func TestToggleWaiverPropagatesAuditTransactionFailure(t *testing.T) {
	project := makeProject(true)
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	storeErr := errors.New("audit insert failed")
	pr := &mockProjectRepo{
		getBySlugFn: func(context.Context, string) (port.Project, error) {
			return project, nil
		},
	}
	wr := &mockWaiverRepo{
		toggleWithEventFn: func(context.Context, string, string, string) (port.Waiver, error) {
			return port.Waiver{}, storeErr
		},
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Waivers: wr}})

	resp, err := uc.ToggleWaiver(sessionCtx("admin", auth.RoleAdmin), "my-app", waiverID, "actor-1")
	assert.Nil(t, resp)
	require.ErrorIs(t, err, storeErr)
}

func TestCheckWaiverMatch_NoActiveWaiver(t *testing.T) {
	_, _, wr, uc := testCheckWaiverMatchDeps(t)
	wr.listActiveFn = func(ctx context.Context, projectID string) ([]port.Waiver, error) {
		return nil, nil
	}

	matched, err := uc.CheckWaiverMatch(sessionCtx("admin", auth.RoleAdmin), "my-app", "00000000-0000-0000-0000-0000000000a1")
	require.NoError(t, err)
	assert.False(t, matched)
}

func TestCheckWaiverMatch_SeverityCondition(t *testing.T) {
	_, _, wr, uc := testCheckWaiverMatchDeps(t)
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	wr.listActiveFn = func(ctx context.Context, projectID string) ([]port.Waiver, error) {
		return []port.Waiver{{ID: waiverID}}, nil
	}
	wr.listConditionsFn = func(ctx context.Context, wID string) ([]port.WaiverCondition, error) {
		return []port.WaiverCondition{{
			Field:    "severity_rank",
			Operator: "gte",
			Value:    "3",
		}}, nil
	}

	matched, err := uc.CheckWaiverMatch(sessionCtx("admin", auth.RoleAdmin), "my-app", "00000000-0000-0000-0000-0000000000a1")
	require.NoError(t, err)
	assert.True(t, matched, "finding severity 3 must match a severity_rank gte 3 waiver")
}

// TestCheckWaiverMatch_ContextOR pins the semantic contract CheckWaiverMatch
// now shares with gate.Evaluate: waiver contexts OR together — a finding in
// environment A is waived when the waiver carries contexts for A and B, even
// though the B context does not match. The pre-dedup CheckWaiverMatch required
// every context to match (AND), silently disagreeing with the gate.
func TestCheckWaiverMatch_ContextOR(t *testing.T) {
	_, fr, wr, uc := testCheckWaiverMatchDeps(t)

	envA := "00000000-0000-0000-0000-0000000000c1"
	envB := "00000000-0000-0000-0000-0000000000d1"
	fr.getFindingContextFn = func(ctx context.Context, findingID string) (port.FindingContext, error) {
		return port.FindingContext{EnvironmentID: envA}, nil
	}

	waiverID := "00000000-0000-0000-0000-0000000000b1"
	wr.listActiveFn = func(ctx context.Context, projectID string) ([]port.Waiver, error) {
		return []port.Waiver{{ID: waiverID}}, nil
	}
	wr.listContextsFn = func(ctx context.Context, wID string) ([]port.WaiverContext, error) {
		return []port.WaiverContext{
			{EnvironmentID: envA},
			{EnvironmentID: envB},
		}, nil
	}

	matched, err := uc.CheckWaiverMatch(sessionCtx("admin", auth.RoleAdmin), "my-app", "00000000-0000-0000-0000-0000000000a1")
	require.NoError(t, err)
	assert.True(t, matched, "waiver contexts must OR together: env A finding matches the A context even with a B context present")
}

func TestCheckWaiverMatch_InvalidFindingID(t *testing.T) {
	_, _, _, uc := testCheckWaiverMatchDeps(t)

	_, err := uc.CheckWaiverMatch(context.Background(), "my-app", "not-a-uuid")
	require.Error(t, err)
}

func TestCheckWaiverMatch_RejectsFindingFromAnotherProject(t *testing.T) {
	_, fr, _, uc := testCheckWaiverMatchDeps(t)
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return port.Finding{ID: id, ProjectID: "00000000-0000-0000-0000-000000000099"}, nil
	}

	_, err := uc.CheckWaiverMatch(sessionCtx("admin", auth.RoleAdmin), "my-app", "00000000-0000-0000-0000-0000000000a1")
	require.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestGateWaiverRepo_ListActiveWaivers_Batched(t *testing.T) {
	w1 := "00000000-0000-0000-0000-000000000001"
	w2 := "00000000-0000-0000-0000-000000000002"

	wr := &mockWaiverRepo{
		listActiveFn: func(ctx context.Context, projectID string) ([]port.Waiver, error) {
			return []port.Waiver{{ID: w1}, {ID: w2}}, nil
		},
		listConditionsByWaiverIDsFn: func(ctx context.Context, ids []string) ([]port.WaiverCondition, error) {
			assert.ElementsMatch(t, []string{w1, w2}, ids)
			return []port.WaiverCondition{
				{ID: "c1", WaiverID: w1, Field: "cve_id", Operator: "eq", Value: "CVE-2024-1"},
				{ID: "c2", WaiverID: w2, Field: "severity", Operator: "eq", Value: "critical"},
			}, nil
		},
		listContextsByWaiverIDsFn: func(ctx context.Context, ids []string) ([]port.WaiverContext, error) {
			return []port.WaiverContext{
				{ID: "ctx1", WaiverID: w1, EnvironmentID: "env1"},
			}, nil
		},
		listFindingTargetsByWaiverIDsFn: func(ctx context.Context, ids []string) ([]port.WaiverFindingTarget, error) {
			return []port.WaiverFindingTarget{
				{ID: "t1", WaiverID: w2, FindingID: "f99"},
			}, nil
		},
	}

	repo := &gateWaiverRepo{stores: &port.Stores{Waivers: wr}}
	gateWaivers, err := repo.ListActiveWaivers(context.Background(), "proj1")
	require.NoError(t, err)
	require.Len(t, gateWaivers, 2)

	assert.Equal(t, w1, gateWaivers[0].ID)
	require.Len(t, gateWaivers[0].Conditions, 1)
	assert.Equal(t, "CVE-2024-1", gateWaivers[0].Conditions[0].Value)
	require.Len(t, gateWaivers[0].Contexts, 1)
	assert.Equal(t, "env1", gateWaivers[0].Contexts[0].EnvironmentID)
	assert.Empty(t, gateWaivers[0].Targets)

	assert.Equal(t, w2, gateWaivers[1].ID)
	require.Len(t, gateWaivers[1].Conditions, 1)
	assert.Equal(t, "critical", gateWaivers[1].Conditions[0].Value)
	assert.Empty(t, gateWaivers[1].Contexts)
	require.Len(t, gateWaivers[1].Targets, 1)
	assert.Equal(t, "f99", gateWaivers[1].Targets[0].FindingID)
}

func waiverUsecaseForProject(project port.Project, waivers *mockWaiverRepo, effectiveRole string) *Usecases {
	projects := &mockProjectRepo{
		getBySlugFn: func(context.Context, string) (port.Project, error) {
			return project, nil
		},
		effectiveRoleFn: func(context.Context, string, string) (string, error) {
			return effectiveRole, nil
		},
	}
	return New(Deps{Stores: &port.Stores{Projects: projects, Waivers: waivers}})
}

func TestCreateWaiverPersistsScopedDetailsAndReturnsPublicRepresentation(t *testing.T) {
	project := makeProject(true)
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	actorID := "00000000-0000-0000-0000-000000000040"
	environmentID := "00000000-0000-0000-0000-0000000000c1"
	findingID := "00000000-0000-0000-0000-0000000000d1"
	createdAt := time.Date(2025, 2, 3, 4, 5, 6, 0, time.UTC)
	wr := &mockWaiverRepo{
		createWithDetailsFn: func(_ context.Context, input port.CreateWaiverInput) (port.Waiver, error) {
			assert.Equal(t, project.ID, input.ProjectID)
			assert.Equal(t, "release exception", input.Name)
			assert.Equal(t, "temporary scanner waiver", input.Description)
			assert.True(t, input.Enabled)
			assert.Equal(t, []port.WaiverCondition{{Field: "severity_rank", Operator: "gte", Value: "3"}}, input.Conditions)
			assert.Equal(t, []port.WaiverContext{{EnvironmentID: environmentID}}, input.Contexts)
			assert.Equal(t, []port.WaiverFindingTarget{{FindingID: findingID}}, input.Targets)
			require.NotNil(t, input.Event.ActorID)
			assert.Equal(t, actorID, *input.Event.ActorID)
			assert.Equal(t, "created", input.Event.EventType)
			assert.JSONEq(t, `{}`, string(input.Event.Metadata))
			return port.Waiver{
				ID: waiverID, ProjectID: project.ID, Name: input.Name, Description: input.Description,
				Enabled: true, CreatedAt: createdAt, UpdatedAt: createdAt,
			}, nil
		},
	}
	uc := waiverUsecaseForProject(project, wr, "")

	got, err := uc.CreateWaiver(sessionCtx("admin", auth.RoleAdmin), CreateWaiverInput{
		ProjectSlug: "my-app",
		Name:        "release exception",
		Description: "temporary scanner waiver",
		Conditions:  []CreateWaiverConditionInput{{Field: "severity_rank", Operator: "gte", Value: "3"}},
		Contexts:    []CreateWaiverContextInput{{EnvironmentID: environmentID}},
		TargetIDs:   []string{findingID},
		ActorID:     actorID,
	})

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, waiverID, got.ID)
	assert.Equal(t, "release exception", got.Name)
	assert.True(t, got.Enabled)
	assert.Equal(t, createdAt.Format(time.RFC3339), got.CreatedAt)
	assert.Empty(t, got.Conditions)
	assert.Empty(t, got.Contexts)
	assert.Empty(t, got.Targets)
}

func TestCreateWaiverRejectsMalformedScopeIDsBeforePersisting(t *testing.T) {
	cases := []struct {
		name  string
		input CreateWaiverInput
		field string
	}{
		{
			name:  "environment scope",
			input: CreateWaiverInput{Contexts: []CreateWaiverContextInput{{EnvironmentID: "not-a-uuid"}}},
			field: "environment_id",
		},
		{
			name:  "target scope",
			input: CreateWaiverInput{Contexts: []CreateWaiverContextInput{{TargetID: "not-a-uuid"}}},
			field: "target_id",
		},
		{
			name:  "artifact scope",
			input: CreateWaiverInput{Contexts: []CreateWaiverContextInput{{ArtifactID: "not-a-uuid"}}},
			field: "artifact_id",
		},
		{
			name:  "finding target",
			input: CreateWaiverInput{TargetIDs: []string{"not-a-uuid"}},
			field: "target finding id",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			project := makeProject(true)
			input := tc.input
			input.ProjectSlug = "my-app"
			wr := &mockWaiverRepo{}
			uc := waiverUsecaseForProject(project, wr, "")

			_, err := uc.CreateWaiver(sessionCtx("admin", auth.RoleAdmin), input)

			require.Error(t, err)
			assert.ErrorContains(t, err, tc.field)
		})
	}
}

func TestCreateWaiverRequiresProjectAdministrator(t *testing.T) {
	project := makeProject(true)
	wr := &mockWaiverRepo{}
	uc := waiverUsecaseForProject(project, wr, auth.RoleViewer)

	_, err := uc.CreateWaiver(sessionCtx("viewer", auth.RoleViewer), CreateWaiverInput{
		ProjectSlug: "my-app",
		Name:        "release exception",
	})

	require.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestListWaiversReturnsProjectWaivers(t *testing.T) {
	project := makeProject(true)
	createdAt := time.Date(2025, 3, 4, 5, 6, 7, 0, time.UTC)
	wr := &mockWaiverRepo{
		listFn: func(_ context.Context, projectID string) ([]port.Waiver, error) {
			assert.Equal(t, project.ID, projectID)
			return []port.Waiver{
				{ID: "w1", ProjectID: project.ID, Name: "one", Enabled: true, CreatedAt: createdAt, UpdatedAt: createdAt},
				{ID: "w2", ProjectID: project.ID, Name: "two", Enabled: false, CreatedAt: createdAt, UpdatedAt: createdAt},
			}, nil
		},
	}
	uc := waiverUsecaseForProject(project, wr, "")

	got, err := uc.ListWaivers(context.Background(), "my-app")

	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "one", got[0].Name)
	assert.True(t, got[0].Enabled)
	assert.Equal(t, "two", got[1].Name)
	assert.False(t, got[1].Enabled)
	assert.Equal(t, createdAt.Format(time.RFC3339), got[1].UpdatedAt)
}

func TestGetWaiverReturnsItsConditionsContextsAndTargets(t *testing.T) {
	project := makeProject(true)
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	environmentID := "00000000-0000-0000-0000-0000000000c1"
	findingID := "00000000-0000-0000-0000-0000000000d1"
	wr := &mockWaiverRepo{
		getByIDFn: func(_ context.Context, id, projectID string) (port.Waiver, error) {
			assert.Equal(t, waiverID, id)
			assert.Equal(t, project.ID, projectID)
			return port.Waiver{ID: id, ProjectID: projectID, Name: "release exception"}, nil
		},
		listConditionsFn: func(context.Context, string) ([]port.WaiverCondition, error) {
			return []port.WaiverCondition{{ID: "c1", Field: "severity_rank", Operator: "gte", Value: "3"}}, nil
		},
		listContextsFn: func(context.Context, string) ([]port.WaiverContext, error) {
			return []port.WaiverContext{{ID: "x1", EnvironmentID: environmentID}}, nil
		},
		listFindingTargetsFn: func(context.Context, string) ([]port.WaiverFindingTarget, error) {
			return []port.WaiverFindingTarget{{ID: "t1", FindingID: findingID}}, nil
		},
	}
	uc := waiverUsecaseForProject(project, wr, "")

	got, err := uc.GetWaiver(context.Background(), "my-app", waiverID)

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "release exception", got.Name)
	require.Len(t, got.Conditions, 1)
	assert.Equal(t, "severity_rank", got.Conditions[0].Field)
	require.Len(t, got.Contexts, 1)
	assert.Equal(t, environmentID, got.Contexts[0].EnvironmentID)
	require.Len(t, got.Targets, 1)
	assert.Equal(t, findingID, got.Targets[0].FindingID)
}

func TestUpdateWaiverReplacesProvidedDetailsAndRecordsActor(t *testing.T) {
	project := makeProject(true)
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	actorID := "00000000-0000-0000-0000-000000000040"
	environmentID := "00000000-0000-0000-0000-0000000000c1"
	findingID := "00000000-0000-0000-0000-0000000000d1"
	wr := &mockWaiverRepo{
		updateWithDetailsFn: func(_ context.Context, waiver port.Waiver, conditions *[]port.WaiverCondition, contexts *[]port.WaiverContext, targets *[]port.WaiverFindingTarget, event port.WaiverEventInput) (port.Waiver, error) {
			assert.Equal(t, waiverID, waiver.ID)
			assert.Equal(t, project.ID, waiver.ProjectID)
			assert.Equal(t, "updated exception", waiver.Name)
			require.NotNil(t, conditions)
			assert.Equal(t, []port.WaiverCondition{{Field: "cve_id", Operator: "eq", Value: "CVE-2025-1"}}, *conditions)
			require.NotNil(t, contexts)
			assert.Equal(t, []port.WaiverContext{{EnvironmentID: environmentID}}, *contexts)
			require.NotNil(t, targets)
			assert.Equal(t, []port.WaiverFindingTarget{{FindingID: findingID}}, *targets)
			assert.Equal(t, "updated", event.EventType)
			require.NotNil(t, event.ActorID)
			assert.Equal(t, actorID, *event.ActorID)
			return waiver, nil
		},
	}
	uc := waiverUsecaseForProject(project, wr, "")

	got, err := uc.UpdateWaiver(sessionCtx("admin", auth.RoleAdmin), UpdateWaiverInput{
		WaiverID:    waiverID,
		ProjectSlug: "my-app",
		Name:        "updated exception",
		Conditions:  []CreateWaiverConditionInput{{Field: "cve_id", Operator: "eq", Value: "CVE-2025-1"}},
		Contexts:    []CreateWaiverContextInput{{EnvironmentID: environmentID}},
		TargetIDs:   []string{findingID},
		ActorID:     actorID,
	})

	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "updated exception", got.Name)
}

func TestUpdateWaiverPreservesOmittedDetailsAndClearsExplicitEmptyDetails(t *testing.T) {
	project := makeProject(true)
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	wr := &mockWaiverRepo{
		updateWithDetailsFn: func(_ context.Context, _ port.Waiver, conditions *[]port.WaiverCondition, contexts *[]port.WaiverContext, targets *[]port.WaiverFindingTarget, _ port.WaiverEventInput) (port.Waiver, error) {
			assert.Nil(t, conditions)
			require.NotNil(t, contexts)
			assert.Empty(t, *contexts)
			assert.Nil(t, targets)
			return port.Waiver{ID: waiverID, ProjectID: project.ID, Name: "unchanged scopes"}, nil
		},
	}
	uc := waiverUsecaseForProject(project, wr, "")

	_, err := uc.UpdateWaiver(sessionCtx("admin", auth.RoleAdmin), UpdateWaiverInput{
		WaiverID:    waiverID,
		ProjectSlug: "my-app",
		Contexts:    []CreateWaiverContextInput{},
	})

	require.NoError(t, err)
}

func TestListWaiverEventsReturnsAuditHistory(t *testing.T) {
	project := makeProject(true)
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	createdAt := time.Date(2025, 4, 5, 6, 7, 8, 0, time.UTC)
	wr := &mockWaiverRepo{
		getByIDFn: func(_ context.Context, id, projectID string) (port.Waiver, error) {
			assert.Equal(t, waiverID, id)
			assert.Equal(t, project.ID, projectID)
			return port.Waiver{ID: id, ProjectID: projectID}, nil
		},
		listEventsFn: func(_ context.Context, id string) ([]port.WaiverEvent, error) {
			assert.Equal(t, waiverID, id)
			return []port.WaiverEvent{{
				ID: "event-1", WaiverID: id, EventType: "disabled", ActorID: "actor-1",
				Metadata: []byte(`{"source":"console"}`), CreatedAt: createdAt,
			}}, nil
		},
	}
	uc := waiverUsecaseForProject(project, wr, "")

	got, err := uc.ListWaiverEvents(context.Background(), "my-app", waiverID)

	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "disabled", got[0].EventType)
	assert.Equal(t, "actor-1", got[0].ActorID)
	assert.JSONEq(t, `{"source":"console"}`, string(got[0].Metadata))
	assert.Equal(t, createdAt.Format(time.RFC3339), got[0].CreatedAt)
}

func TestDeleteWaiverIsScopedToProject(t *testing.T) {
	project := makeProject(true)
	waiverID := "00000000-0000-0000-0000-0000000000b1"
	wr := &mockWaiverRepo{
		deleteFn: func(_ context.Context, id, projectID string) error {
			assert.Equal(t, waiverID, id)
			assert.Equal(t, project.ID, projectID)
			return nil
		},
	}
	uc := waiverUsecaseForProject(project, wr, "")

	err := uc.DeleteWaiver(sessionCtx("admin", auth.RoleAdmin), "my-app", waiverID)

	require.NoError(t, err)
}
