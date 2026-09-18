package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/port"
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
		return port.Finding{ID: findingID, FindingKind: "sca", CurrentSeverityRank: 3}, nil
	}

	uc := New(Deps{
		Stores: &port.Stores{Projects: pr, Findings: fr, Waivers: wr},
	})
	return pr, fr, wr, uc
}

func TestCheckWaiverMatch_NoActiveWaiver(t *testing.T) {
	_, _, wr, uc := testCheckWaiverMatchDeps(t)
	wr.listActiveFn = func(ctx context.Context, projectID string) ([]port.Waiver, error) {
		return nil, nil
	}

	matched, err := uc.CheckWaiverMatch(context.Background(), "my-app", "00000000-0000-0000-0000-0000000000a1")
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

	matched, err := uc.CheckWaiverMatch(context.Background(), "my-app", "00000000-0000-0000-0000-0000000000a1")
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

	matched, err := uc.CheckWaiverMatch(context.Background(), "my-app", "00000000-0000-0000-0000-0000000000a1")
	require.NoError(t, err)
	assert.True(t, matched, "waiver contexts must OR together: env A finding matches the A context even with a B context present")
}

func TestCheckWaiverMatch_InvalidFindingID(t *testing.T) {
	_, _, _, uc := testCheckWaiverMatchDeps(t)

	_, err := uc.CheckWaiverMatch(context.Background(), "my-app", "not-a-uuid")
	require.Error(t, err)
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
