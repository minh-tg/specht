package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// A waiver the project does not have answers not found whatever the body says,
// so a foreign id and a missing id cannot be told apart by how the body fails.
func TestUpdateWaiverOfAnUnknownWaiverIsNotFoundBeforeTheBodyIsChecked(t *testing.T) {
	project := makeProject(true)
	wr := &mockWaiverRepo{
		getByIDFn: func(context.Context, string, string) (port.Waiver, error) { return port.Waiver{}, port.ErrNotFound },
		updateWithDetailsFn: func(context.Context, port.Waiver, *port.WaiverExpiry, *[]port.WaiverCondition, *[]port.WaiverContext, *[]port.WaiverFindingTarget, port.WaiverEventInput) (port.Waiver, error) {
			t.Fatal("an unknown waiver must not reach the update")
			return port.Waiver{}, nil
		},
	}
	uc := waiverUsecaseForProject(project, wr, "")
	admin := sessionCtx("admin", auth.RoleAdmin)
	id := "00000000-0000-0000-0000-0000000000b1"

	for name, input := range map[string]UpdateWaiverInput{
		"emptied conditions": {Conditions: []CreateWaiverConditionInput{}},
		"invalid condition":  {Conditions: []CreateWaiverConditionInput{{Field: "severity", Operator: "eq", Value: "HIGH"}}},
		"emptied contexts":   {Contexts: []CreateWaiverContextInput{}},
		"plain rename":       {Name: "renamed"},
	} {
		t.Run(name, func(t *testing.T) {
			input.ProjectSlug, input.WaiverID = "my-app", id
			_, err := uc.UpdateWaiver(admin, input)
			require.ErrorIs(t, err, port.ErrNotFound)
		})
	}
}
