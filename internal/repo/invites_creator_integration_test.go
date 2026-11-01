//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// inviteBy stores an invite made by the given account.
func (f *inviteFixture) inviteBy(t *testing.T, creatorID, token, role string) {
	t.Helper()
	_, err := f.stores.Invites.Create(context.Background(), port.NewInvite{
		TokenHash: hashOf(token), ProjectID: f.projectID, Role: role,
		CreatedBy: creatorID, ExpiresAt: inOneDay(),
	})
	require.NoError(t, err)
}

// requireLinkRefused checks that every way of using the link answers like a
// dead link and leaves no account or membership behind.
func requireLinkRefused(t *testing.T, f *inviteFixture, token, why string) {
	t.Helper()
	ctx := context.Background()
	existing := newUser(t, f.repos, "existing-"+token+"@test.com", "member")

	_, err := f.stores.Invites.Lookup(ctx, hashOf(token))
	assert.ErrorIs(t, err, port.ErrNotFound, "%s: lookup", why)
	_, err = f.stores.Invites.AcceptAsUser(ctx, hashOf(token), existing.ID)
	assert.ErrorIs(t, err, port.ErrNotFound, "%s: join", why)
	_, err = f.stores.Invites.AcceptWithNewAccount(ctx, hashOf(token),
		port.InviteeAccount{Email: "newcomer-" + token + "@test.com", PasswordHash: "$2a$10$hash"})
	assert.ErrorIs(t, err, port.ErrNotFound, "%s: accept", why)

	_, err = f.repos.Users.GetByEmail(ctx, "newcomer-"+token+"@test.com")
	assert.ErrorIs(t, err, pgx.ErrNoRows, "%s: no account was created", why)
	isMember, err := f.stores.Projects.IsMember(ctx, f.projectID, existing.ID)
	require.NoError(t, err)
	assert.False(t, isMember, "%s: no membership was granted", why)
}

func requireLinkWorks(t *testing.T, f *inviteFixture, token, role string) {
	t.Helper()
	ctx := context.Background()
	existing := newUser(t, f.repos, "joiner-"+token+"@test.com", "member")
	_, err := f.stores.Invites.Lookup(ctx, hashOf(token))
	require.NoError(t, err)
	accepted, err := f.stores.Invites.AcceptAsUser(ctx, hashOf(token), existing.ID)
	require.NoError(t, err)
	assert.Equal(t, role, accepted.Role)
}

func TestInvites_ClaimNeedsTheCreatorsCurrentAuthority(t *testing.T) {
	ctx := context.Background()

	t.Run("creator deactivated", func(t *testing.T) {
		repos, cleanup := setupTestDB(t)
		defer cleanup()
		f := newInviteFixture(t, repos)
		creator := newUser(t, repos, "mgr@test.com", "member")
		_, err := f.stores.Projects.UpsertMember(ctx, f.projectID, creator.ID, "manager")
		require.NoError(t, err)
		f.inviteBy(t, creator.ID, "tok", "manager")

		// Written straight to the row, so the claim is the only thing that can refuse.
		_, err = repos.pool.Exec(ctx, "UPDATE users SET disabled_at = NOW() WHERE id = $1", creator.ID)
		require.NoError(t, err)
		requireLinkRefused(t, f, "tok", "deactivated creator")

		_, err = f.stores.Users.SetDisabled(ctx, creator.ID, false)
		require.NoError(t, err)
		requireLinkWorks(t, f, "tok", "manager")
	})

	t.Run("creator removed from the project", func(t *testing.T) {
		repos, cleanup := setupTestDB(t)
		defer cleanup()
		f := newInviteFixture(t, repos)
		creator := newUser(t, repos, "mgr@test.com", "member")
		_, err := f.stores.Projects.UpsertMember(ctx, f.projectID, creator.ID, "manager")
		require.NoError(t, err)
		f.inviteBy(t, creator.ID, "tok", "manager")

		require.NoError(t, f.stores.Projects.DeleteMember(ctx, f.projectID, creator.ID))
		requireLinkRefused(t, f, "tok", "removed creator")
	})

	t.Run("creator demoted to member, then promoted back", func(t *testing.T) {
		repos, cleanup := setupTestDB(t)
		defer cleanup()
		f := newInviteFixture(t, repos)
		creator := newUser(t, repos, "mgr@test.com", "member")
		_, err := f.stores.Projects.UpsertMember(ctx, f.projectID, creator.ID, "manager")
		require.NoError(t, err)
		f.inviteBy(t, creator.ID, "manager-link", "manager")
		f.inviteBy(t, creator.ID, "member-link", "member")

		_, err = f.stores.Projects.UpsertMember(ctx, f.projectID, creator.ID, "member")
		require.NoError(t, err)
		requireLinkRefused(t, f, "manager-link", "demoted creator, manager link")
		requireLinkRefused(t, f, "member-link", "demoted creator, member link")

		_, err = f.stores.Projects.UpsertMember(ctx, f.projectID, creator.ID, "manager")
		require.NoError(t, err)
		requireLinkWorks(t, f, "manager-link", "manager")
		requireLinkWorks(t, f, "member-link", "member")
	})

	t.Run("global admin demoted", func(t *testing.T) {
		repos, cleanup := setupTestDB(t)
		defer cleanup()
		f := newInviteFixture(t, repos)
		// The fixture's inviter is the second admin, so the last-admin guard allows the demotion.
		creator := newUser(t, repos, "ex-admin@test.com", "admin")
		f.inviteBy(t, creator.ID, "tok", "manager")

		_, err := f.stores.Users.ChangeRole(ctx, creator.ID, "member")
		require.NoError(t, err)
		requireLinkRefused(t, f, "tok", "demoted admin")

		_, err = f.stores.Users.ChangeRole(ctx, creator.ID, "admin")
		require.NoError(t, err)
		requireLinkWorks(t, f, "tok", "manager")
	})

	t.Run("creator holds the role only through a team", func(t *testing.T) {
		repos, cleanup := setupTestDB(t)
		defer cleanup()
		f := newInviteFixture(t, repos)
		creator := newUser(t, repos, "teammate@test.com", "member")
		_, err := f.stores.Projects.UpsertMember(ctx, f.projectID, creator.ID, "member")
		require.NoError(t, err)
		teams := &pgTeamPort{q: sqlc.New(repos.pool)}
		team, err := teams.CreateTeam(ctx, "backend", "")
		require.NoError(t, err)
		_, err = teams.UpsertTeamMember(ctx, team.ID, creator.ID, "member")
		require.NoError(t, err)
		_, err = teams.LinkProjectTeam(ctx, f.projectID, team.ID, "manager")
		require.NoError(t, err)
		f.inviteBy(t, creator.ID, "member-link", "member")
		f.inviteBy(t, creator.ID, "manager-link", "manager")

		requireLinkRefused(t, f, "manager-link", "team role cannot vouch for a manager link")
		requireLinkWorks(t, f, "member-link", "member")

		f.inviteBy(t, creator.ID, "member-link-2", "member")
		require.NoError(t, teams.UnlinkProjectTeam(ctx, f.projectID, team.ID))
		requireLinkRefused(t, f, "member-link-2", "team link removed")
	})

	t.Run("creator account gone", func(t *testing.T) {
		repos, cleanup := setupTestDB(t)
		defer cleanup()
		f := newInviteFixture(t, repos)
		f.invite(t, "tok", "member", nil, inOneDay())

		_, err := repos.pool.Exec(ctx, "UPDATE invites SET created_by = NULL")
		require.NoError(t, err)
		requireLinkRefused(t, f, "tok", "no creator")
	})

	t.Run("creator unchanged", func(t *testing.T) {
		repos, cleanup := setupTestDB(t)
		defer cleanup()
		f := newInviteFixture(t, repos)
		creator := newUser(t, repos, "mgr@test.com", "member")
		_, err := f.stores.Projects.UpsertMember(ctx, f.projectID, creator.ID, "manager")
		require.NoError(t, err)
		f.inviteBy(t, creator.ID, "tok", "manager")
		requireLinkWorks(t, f, "tok", "manager")
	})
}

// A change to the creator that has not committed yet holds a lock on the row
// the claim reads. The claim has to wait for it and decide on what it finds,
// not on the state from before.
func TestInvites_ClaimWaitsForAConcurrentChangeToTheCreator(t *testing.T) {
	tests := []struct {
		name   string
		change string
	}{
		{"deactivation", "UPDATE users SET disabled_at = NOW() WHERE id = $1"},
		{"demotion", "UPDATE project_members SET role = 'member' WHERE user_id = $1"},
		{"removal", "DELETE FROM project_members WHERE user_id = $1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repos, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := context.Background()
			f := newInviteFixture(t, repos)
			creator := newUser(t, repos, "mgr@test.com", "member")
			_, err := f.stores.Projects.UpsertMember(ctx, f.projectID, creator.ID, "manager")
			require.NoError(t, err)
			f.inviteBy(t, creator.ID, "tok", "manager")

			tx, err := repos.pool.Begin(ctx)
			require.NoError(t, err)
			defer func() { _ = tx.Rollback(ctx) }()
			_, err = tx.Exec(ctx, tc.change, creator.ID)
			require.NoError(t, err)

			done := make(chan error, 1)
			go func() {
				_, err := f.stores.Invites.AcceptWithNewAccount(ctx, hashOf("tok"),
					port.InviteeAccount{Email: "newcomer@test.com", PasswordHash: "$2a$10$hash"})
				done <- err
			}()

			select {
			case err := <-done:
				t.Fatalf("the claim finished while the change was open: %v", err)
			case <-time.After(500 * time.Millisecond):
			}
			require.NoError(t, tx.Commit(ctx))

			select {
			case err := <-done:
				assert.ErrorIs(t, err, port.ErrNotFound)
			case <-time.After(5 * time.Second):
				t.Fatal("the claim did not finish after the change committed")
			}
			_, err = repos.Users.GetByEmail(ctx, "newcomer@test.com")
			assert.ErrorIs(t, err, pgx.ErrNoRows)
		})
	}
}

func TestInvites_DeactivationRevokesTheOpenLinksTheAccountMade(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	f := newInviteFixture(t, repos)
	leaver := newUser(t, repos, "leaver@test.com", "member")
	stayer := newUser(t, repos, "stayer@test.com", "member")
	for _, u := range []port.User{leaver, stayer} {
		_, err := f.stores.Projects.UpsertMember(ctx, f.projectID, u.ID, "manager")
		require.NoError(t, err)
	}
	f.inviteBy(t, leaver.ID, "leaver-open", "member")
	f.inviteBy(t, leaver.ID, "leaver-used", "member")
	f.inviteBy(t, stayer.ID, "stayer-open", "member")
	joiner := newUser(t, repos, "joiner@test.com", "member")
	_, err := f.stores.Invites.AcceptAsUser(ctx, hashOf("leaver-used"), joiner.ID)
	require.NoError(t, err)

	_, _, err = f.stores.Users.Deactivate(ctx, leaver.ID, true)
	require.NoError(t, err)

	var revoked, accepted, open int
	require.NoError(t, repos.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM invites WHERE created_by = $1 AND revoked_at IS NOT NULL", leaver.ID).Scan(&revoked))
	assert.Equal(t, 1, revoked, "the open link is revoked")
	require.NoError(t, repos.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM invites WHERE created_by = $1 AND accepted_at IS NOT NULL AND revoked_at IS NULL", leaver.ID).Scan(&accepted))
	assert.Equal(t, 1, accepted, "a link already used is left alone")
	require.NoError(t, repos.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM invites WHERE created_by = $1 AND revoked_at IS NULL AND accepted_at IS NULL", stayer.ID).Scan(&open))
	assert.Equal(t, 1, open, "another account's link is left alone")

	count, err := f.stores.Invites.CountPending(ctx, f.projectID)
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
