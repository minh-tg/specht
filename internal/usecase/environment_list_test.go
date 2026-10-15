package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

func TestListEnvironments_ReportsExposureAndSensitivity(t *testing.T) {
	pr := projectUpdateRepos()
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return []port.ProjectMember{{ProjectID: projectID, UserID: "u1", Role: auth.RoleViewer}}, nil
	}
	envs := &mockEnvironmentRepo{}
	envs.listFn = func(ctx context.Context, projectID string) ([]port.Environment, error) {
		return []port.Environment{
			{ID: "00000000-0000-0000-0000-0000000000e1", ProjectID: projectID, Name: "production", Tier: "production", InternetFacing: true, DataSensitivity: "restricted"},
		}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Environments: envs}})

	got, err := uc.ListEnvironments(sessionCtx("u1", auth.RoleViewer), "my-app")

	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.True(t, got[0].InternetFacing)
	assert.Equal(t, "restricted", got[0].DataSensitivity)
}
