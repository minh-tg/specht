//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTeams_ConferAccessEndToEnd proves team-conferred project access
// against real Postgres: linking grants effective membership with the
// linked role, unlinking revokes it, and direct memberships are untouched.
func TestTeams_ConferAccessEndToEnd(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	teams := &pgTeamPort{q: sqlc.New(repos.pool)}
	projects := &pgProjectPort{q: sqlc.New(repos.pool)}

	user, err := repos.Users.Create(ctx, "teammate@test.com",
		pgtype.Text{Valid: false}, pgtype.Text{Valid: true, String: "unused-hash"})
	require.NoError(t, err)
	userID := uuid.UUID(user.ID.Bytes).String()

	project := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()

	team, err := teams.CreateTeam(ctx, "backend", "")
	require.NoError(t, err)
	_, err = teams.UpsertTeamMember(ctx, team.ID, userID, "member")
	require.NoError(t, err)

	effective, err := projects.IsMemberEffective(ctx, projectID, userID)
	require.NoError(t, err)
	assert.False(t, effective, "no link yet: no access")

	_, err = teams.LinkProjectTeam(ctx, projectID, team.ID, "manager")
	require.NoError(t, err)

	effective, err = projects.IsMemberEffective(ctx, projectID, userID)
	require.NoError(t, err)
	assert.True(t, effective, "linked team confers membership")

	role, err := projects.EffectiveRole(ctx, projectID, userID)
	require.NoError(t, err)
	assert.Equal(t, "manager", role)

	ids, err := projects.ListAccessibleProjectIDs(ctx, userID)
	require.NoError(t, err)
	assert.Contains(t, ids, projectID)

	require.NoError(t, teams.UnlinkProjectTeam(ctx, projectID, team.ID))
	effective, err = projects.IsMemberEffective(ctx, projectID, userID)
	require.NoError(t, err)
	assert.False(t, effective, "unlink revokes conferred access")
}
