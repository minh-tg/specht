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

// A person sees the teams they belong to and the teams linked to a project they
// reach, directly or through a team of their own, and no other.
func TestTeamVisibility_FollowsMembershipAndProjectAccess(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	projects := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}
	teams := &pgTeamPort{q: sqlc.New(repos.pool)}

	projX := uuid.UUID(createTestProject(t, repos).ID.Bytes).String()
	projY := uuid.UUID(createTestProject(t, repos).ID.Bytes).String()
	direct := newTestUserID(t, repos)
	viaTeam := newTestUserID(t, repos)
	belongs := newTestUserID(t, repos)
	stranger := newTestUserID(t, repos)

	newTeam := func(name string) string {
		team, err := teams.CreateTeam(ctx, name+"-"+uuid.NewString()[:6], "")
		require.NoError(t, err)
		return team.ID
	}
	tOnX := newTeam("on-x")
	tOnY := newTeam("on-y")
	tViaTeam := newTeam("members-of-x")
	tFree := newTeam("free")

	_, err := projects.UpsertMember(ctx, projX, direct, "member")
	require.NoError(t, err)
	_, err = teams.LinkProjectTeam(ctx, projX, tOnX, "member")
	require.NoError(t, err)
	_, err = teams.LinkProjectTeam(ctx, projY, tOnY, "admin")
	require.NoError(t, err)
	_, err = teams.LinkProjectTeam(ctx, projX, tViaTeam, "member")
	require.NoError(t, err)
	_, err = teams.UpsertTeamMember(ctx, tViaTeam, viaTeam, "member")
	require.NoError(t, err)
	_, err = teams.UpsertTeamMember(ctx, tFree, belongs, "member")
	require.NoError(t, err)

	ids := func(userID string) map[string]bool {
		list, err := teams.ListTeamsVisibleTo(ctx, userID)
		require.NoError(t, err)
		out := map[string]bool{}
		for _, tm := range list {
			out[tm.ID] = true
		}
		for _, id := range []string{tOnX, tOnY, tViaTeam, tFree} {
			visible, err := teams.IsTeamVisibleTo(ctx, id, userID)
			require.NoError(t, err)
			assert.Equal(t, out[id], visible, "IsTeamVisibleTo agrees with the list for %s", id)
		}
		return out
	}

	got := ids(direct)
	assert.True(t, got[tOnX] && got[tViaTeam], "teams linked to the caller's project")
	assert.False(t, got[tOnY] || got[tFree])

	got = ids(viaTeam)
	assert.True(t, got[tOnX] && got[tViaTeam], "access through a team counts like a direct row, and the team itself is theirs")
	assert.False(t, got[tOnY] || got[tFree])

	got = ids(belongs)
	assert.True(t, got[tFree], "a team the person belongs to, linked nowhere")
	assert.False(t, got[tOnX] || got[tOnY] || got[tViaTeam])

	assert.Empty(t, ids(stranger))

	visible, err := teams.IsTeamVisibleTo(ctx, uuid.NewString(), direct)
	require.NoError(t, err)
	assert.False(t, visible, "an unknown team is not visible")
}
