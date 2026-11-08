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

// TestCountOtherWaiverDeciders proves who counts as someone else who can decide
// a waiver request: a manager or admin reached directly or through a team, and a
// global admin who is on the project. A plain member, a deactivated manager, the
// system account and a global admin who is not on the project do not count.
func TestCountOtherWaiverDeciders(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	teams := &pgTeamPort{q: sqlc.New(repos.pool)}
	projects := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}

	newUser := func(email string) string {
		t.Helper()
		user, err := repos.Users.Create(ctx, email, pgtype.Text{}, pgtype.Text{Valid: true, String: "unused-hash"})
		require.NoError(t, err)
		return uuid.UUID(user.ID.Bytes).String()
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := repos.pool.Exec(ctx, sql, args...)
		require.NoError(t, err)
	}
	others := func(projectID, userID string) int {
		t.Helper()
		n, err := projects.CountOtherWaiverDeciders(ctx, projectID, userID)
		require.NoError(t, err)
		return n
	}

	projectID := uuid.UUID(createTestProject(t, repos).ID.Bytes).String()
	requester := newUser("requester@test.com")
	_, err := projects.UpsertMember(ctx, projectID, requester, "manager")
	require.NoError(t, err)

	// People who cannot decide, or are not on the project.
	member := newUser("member@test.com")
	_, err = projects.UpsertMember(ctx, projectID, member, "member")
	require.NoError(t, err)
	disabled := newUser("gone@test.com")
	_, err = projects.UpsertMember(ctx, projectID, disabled, "manager")
	require.NoError(t, err)
	exec(`UPDATE users SET disabled_at = now() WHERE id = $1`, disabled)
	exec(`INSERT INTO project_members (project_id, user_id, role)
		SELECT $1, id, 'manager' FROM users WHERE email = 'system@specht.local'`, projectID)
	outsideAdmin := newUser("outside-admin@test.com")
	exec(`UPDATE users SET role = 'admin' WHERE id = $1`, outsideAdmin)

	assert.Equal(t, 0, others(projectID, requester), "nobody else can decide")

	// A manager through a team counts.
	teamManager := newUser("team-manager@test.com")
	team, err := teams.CreateTeam(ctx, "reviewers", "")
	require.NoError(t, err)
	_, err = teams.UpsertTeamMember(ctx, team.ID, teamManager, "member")
	require.NoError(t, err)
	_, err = teams.LinkProjectTeam(ctx, projectID, team.ID, "manager")
	require.NoError(t, err)
	assert.Equal(t, 1, others(projectID, requester), "a team-granted manager can decide")
	assert.Equal(t, 1, others(projectID, teamManager), "the direct manager counts for the team manager")
	require.NoError(t, teams.UnlinkProjectTeam(ctx, projectID, team.ID))

	// A global admin on the project counts, even as a plain member.
	exec(`UPDATE users SET role = 'admin' WHERE id = $1`, member)
	assert.Equal(t, 1, others(projectID, requester), "a global admin on the project can decide")
	exec(`UPDATE users SET role = 'member' WHERE id = $1`, member)

	// A second direct manager counts once, even when a team reaches them too.
	second := newUser("second@test.com")
	_, err = projects.UpsertMember(ctx, projectID, second, "admin")
	require.NoError(t, err)
	_, err = teams.UpsertTeamMember(ctx, team.ID, second, "member")
	require.NoError(t, err)
	_, err = teams.LinkProjectTeam(ctx, projectID, team.ID, "manager")
	require.NoError(t, err)
	assert.Equal(t, 2, others(projectID, requester), "the project admin and the team manager")
}
