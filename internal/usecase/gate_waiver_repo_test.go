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
