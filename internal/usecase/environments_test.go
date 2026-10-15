package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const environmentFixtureID = "00000000-0000-0000-0000-0000000000e1"

type environmentCall struct {
	id, projectID, tier, sensitivity string
	internetFacing                   bool
}

// environmentUsecase wires a project whose members are the given roles and an
// environment store that records its update calls.
func environmentUsecase(role string, calls *[]environmentCall) *Usecases {
	pr := projectUpdateRepos()
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return []port.ProjectMember{{ProjectID: projectID, UserID: "u1", Role: role}}, nil
	}
	envs := &mockEnvironmentRepo{}
	envs.updateFn = func(ctx context.Context, id, projectID, tier string, internetFacing bool, sensitivity string) (port.Environment, error) {
		*calls = append(*calls, environmentCall{id, projectID, tier, sensitivity, internetFacing})
		if id != environmentFixtureID {
			return port.Environment{}, port.ErrNotFound
		}
		return port.Environment{ID: id, ProjectID: projectID, Name: "production", Tier: tier, InternetFacing: internetFacing, DataSensitivity: sensitivity}, nil
	}
	return New(Deps{Stores: &port.Stores{Projects: pr, Environments: envs}})
}

func environmentInput() UpdateEnvironmentInput {
	return UpdateEnvironmentInput{
		ProjectSlug:     "my-app",
		EnvironmentID:   environmentFixtureID,
		Tier:            "production",
		InternetFacing:  true,
		DataSensitivity: "restricted",
	}
}

func TestUpdateEnvironment_ProjectAdminChangesAllThree(t *testing.T) {
	var calls []environmentCall
	uc := environmentUsecase(auth.RoleAdmin, &calls)

	resp, err := uc.UpdateEnvironment(sessionCtx("u1", auth.RoleViewer), environmentInput())

	require.NoError(t, err)
	assert.Equal(t, []environmentCall{{environmentFixtureID, findingFixtureProjectID, "production", "restricted", true}}, calls)
	assert.Equal(t, "production", resp.Tier)
	assert.True(t, resp.InternetFacing)
	assert.Equal(t, "restricted", resp.DataSensitivity)
}

func TestUpdateEnvironment_GlobalAdminAllowed(t *testing.T) {
	var calls []environmentCall
	uc := environmentUsecase(auth.RoleViewer, &calls)

	_, err := uc.UpdateEnvironment(sessionCtx("someone", auth.RoleAdmin), environmentInput())

	require.NoError(t, err)
	assert.Len(t, calls, 1)
}

func TestUpdateEnvironment_NeedsProjectAdmin(t *testing.T) {
	for name, tc := range map[string]struct {
		role string
		ctx  context.Context
	}{
		"manager":   {auth.RoleManager, sessionCtx("u1", auth.RoleViewer)},
		"member":    {auth.RoleMember, sessionCtx("u1", auth.RoleViewer)},
		"viewer":    {auth.RoleViewer, sessionCtx("u1", auth.RoleViewer)},
		"API key":   {auth.RoleAdmin, apiKeyCtx("k1", findingFixtureProjectID)},
		"anonymous": {auth.RoleAdmin, context.Background()},
	} {
		t.Run(name, func(t *testing.T) {
			var calls []environmentCall
			_, err := environmentUsecase(tc.role, &calls).UpdateEnvironment(tc.ctx, environmentInput())
			assert.ErrorIs(t, err, ErrProjectAccessDenied)
			assert.Empty(t, calls)
		})
	}
}

func TestUpdateEnvironment_RefusesValuesOutsideTheVocabulary(t *testing.T) {
	for name, mutate := range map[string]func(*UpdateEnvironmentInput){
		"tier":        func(in *UpdateEnvironmentInput) { in.Tier = "prod" },
		"empty tier":  func(in *UpdateEnvironmentInput) { in.Tier = "" },
		"sensitivity": func(in *UpdateEnvironmentInput) { in.DataSensitivity = "secret" },
		"empty level": func(in *UpdateEnvironmentInput) { in.DataSensitivity = "" },
	} {
		t.Run(name, func(t *testing.T) {
			var calls []environmentCall
			in := environmentInput()
			mutate(&in)
			_, err := environmentUsecase(auth.RoleAdmin, &calls).UpdateEnvironment(sessionCtx("u1", auth.RoleViewer), in)
			assert.ErrorIs(t, err, ErrInvalidEnvironment)
			assert.Empty(t, calls)
		})
	}
}

func TestUpdateEnvironment_UnknownEnvironment(t *testing.T) {
	var calls []environmentCall
	uc := environmentUsecase(auth.RoleAdmin, &calls)

	in := environmentInput()
	in.EnvironmentID = "00000000-0000-0000-0000-0000000000ff"
	_, err := uc.UpdateEnvironment(sessionCtx("u1", auth.RoleViewer), in)
	assert.ErrorIs(t, err, ErrEnvironmentNotFound)

	in.EnvironmentID = "not-a-uuid"
	_, err = uc.UpdateEnvironment(sessionCtx("u1", auth.RoleViewer), in)
	assert.ErrorIs(t, err, ErrEnvironmentNotFound, "a malformed id is the same answer as an unknown one")
}
