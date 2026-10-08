//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTeams_ListTeamProjectLinksIsScopedToOneTeam(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	teams := &pgTeamPort{q: sqlc.New(repos.pool)}

	projectA := uuid.UUID(createTestProject(t, repos).ID.Bytes).String()
	projectB := uuid.UUID(createTestProject(t, repos).ID.Bytes).String()
	backend, err := teams.CreateTeam(ctx, "backend", "")
	require.NoError(t, err)
	frontend, err := teams.CreateTeam(ctx, "frontend", "")
	require.NoError(t, err)

	links, err := teams.ListTeamProjectLinks(ctx, backend.ID)
	require.NoError(t, err)
	assert.Empty(t, links, "a team with no links lists none")

	_, err = teams.LinkProjectTeam(ctx, projectA, backend.ID, "manager")
	require.NoError(t, err)
	_, err = teams.LinkProjectTeam(ctx, projectB, backend.ID, "member")
	require.NoError(t, err)
	_, err = teams.LinkProjectTeam(ctx, projectA, frontend.ID, "admin")
	require.NoError(t, err)

	links, err = teams.ListTeamProjectLinks(ctx, backend.ID)
	require.NoError(t, err)
	require.Len(t, links, 2, "only this team's links, not the frontend team's")
	roles := map[string]string{}
	for _, l := range links {
		assert.Equal(t, backend.ID, l.TeamID)
		assert.Equal(t, "backend", l.TeamName)
		roles[l.ProjectID] = l.Role
	}
	assert.Equal(t, map[string]string{projectA: "manager", projectB: "member"}, roles)
}
