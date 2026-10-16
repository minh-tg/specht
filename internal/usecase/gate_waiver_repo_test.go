package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGateWaiverRepoFailsClosedWhenScopeDetailsCannotBeLoaded(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind string
	}{
		{name: "conditions", kind: "conditions"},
		{name: "deployment contexts", kind: "contexts"},
		{name: "finding targets", kind: "targets"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storeErr := errors.New("scope detail query failed")
			wr := &mockWaiverRepo{
				listActiveFn: func(context.Context, string) ([]port.Waiver, error) {
					return []port.Waiver{{ID: "waiver-1"}}, nil
				},
				listConditionsByWaiverIDsFn: func(context.Context, []string) ([]port.WaiverCondition, error) {
					if tc.kind == "conditions" {
						return nil, storeErr
					}
					return nil, nil
				},
				listContextsByWaiverIDsFn: func(context.Context, []string) ([]port.WaiverContext, error) {
					if tc.kind == "contexts" {
						return nil, storeErr
					}
					return nil, nil
				},
				listFindingTargetsByWaiverIDsFn: func(context.Context, []string) ([]port.WaiverFindingTarget, error) {
					if tc.kind == "targets" {
						return nil, storeErr
					}
					return nil, nil
				},
			}

			got, err := (&gateWaiverRepo{stores: &port.Stores{Waivers: wr}}).ListActiveWaivers(
				context.Background(),
				"project-1",
			)

			require.ErrorIs(t, err, storeErr)
			assert.Nil(t, got, "incomplete waiver scopes must not be treated as global waivers")
		})
	}
}

func TestGateWaiverRepoCarriesScopeAll(t *testing.T) {
	wr := &mockWaiverRepo{
		listActiveFn: func(context.Context, string) ([]port.Waiver, error) {
			return []port.Waiver{{ID: "w-all", ScopeAll: true}, {ID: "w-none"}}, nil
		},
		listConditionsByWaiverIDsFn: func(context.Context, []string) ([]port.WaiverCondition, error) {
			return nil, nil
		},
		listContextsByWaiverIDsFn: func(context.Context, []string) ([]port.WaiverContext, error) {
			return nil, nil
		},
		listFindingTargetsByWaiverIDsFn: func(context.Context, []string) ([]port.WaiverFindingTarget, error) {
			return nil, nil
		},
	}

	got, err := (&gateWaiverRepo{stores: &port.Stores{Waivers: wr}}).ListActiveWaivers(context.Background(), "project-1")

	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.True(t, got[0].ScopeAll)
	assert.False(t, got[1].ScopeAll)
}

// The gate needs every environment that observed a finding, not just the
// newest scan's, to keep an environment-scoped waiver from covering it.
func TestGateFindingRepoCarriesObservedEnvironments(t *testing.T) {
	candidate := port.GateCandidate{
		Finding: port.Finding{ID: "f1"},
		Context: port.FindingContext{EnvironmentID: "env-dev", EnvironmentIDs: []string{"env-dev", "env-prod"}},
	}
	fr := &mockFindingRepo{
		listGateCandidatesFn: func(context.Context, string, int16) ([]port.GateCandidate, error) {
			return []port.GateCandidate{candidate}, nil
		},
		listIntroducedGateCandidatesFn: func(context.Context, string, string, int16) ([]port.GateCandidate, error) {
			return []port.GateCandidate{candidate}, nil
		},
	}
	repo := &gateFindingRepo{stores: &port.Stores{Findings: fr}}

	all, err := repo.ListBlockingFindings(context.Background(), "project-1", 3)
	require.NoError(t, err)
	require.Len(t, all, 1)
	assert.Equal(t, []string{"env-dev", "env-prod"}, all[0].EnvironmentIDs)

	introduced, err := repo.ListIntroducedGateCandidates(context.Background(), "project-1", "report-1", 3)
	require.NoError(t, err)
	require.Len(t, introduced, 1)
	assert.Equal(t, []string{"env-dev", "env-prod"}, introduced[0].EnvironmentIDs)
}
