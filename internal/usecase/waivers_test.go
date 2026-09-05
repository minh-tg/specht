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
