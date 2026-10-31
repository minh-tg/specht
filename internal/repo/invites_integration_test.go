//go:build integration

package repo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func hashOf(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

type inviteFixture struct {
	stores    *port.Stores
	repos     *Repos
	projectID string
	slug      string
	inviter   port.User
}

func newInviteFixture(t *testing.T, repos *Repos) *inviteFixture {
	t.Helper()
	project := createTestProject(t, repos)
	return &inviteFixture{
		stores:    NewPortStores(repos.pool),
		repos:     repos,
		projectID: uuid.UUID(project.ID.Bytes).String(),
		slug:      project.Slug,
		inviter:   newUser(t, repos, "inviter@test.com", "admin"),
	}
}

func (f *inviteFixture) invite(t *testing.T, token, role string, email *string, expires time.Time) port.Invite {
	t.Helper()
	inv, err := f.stores.Invites.Create(context.Background(), port.NewInvite{
		TokenHash: hashOf(token), ProjectID: f.projectID, Role: role, Email: email,
		CreatedBy: f.inviter.ID, ExpiresAt: expires,
	})
	require.NoError(t, err)
	return inv
}

func inOneDay() time.Time { return time.Now().Add(24 * time.Hour) }

func TestInvites_CreateListLookupRevoke(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	f := newInviteFixture(t, repos)
	email := "new@test.com"

	inv := f.invite(t, "token-a", "manager", &email, inOneDay())
	f.invite(t, "token-b", "member", nil, inOneDay())

	count, err := f.stores.Invites.CountPending(ctx, f.projectID)
	require.NoError(t, err)
	assert.EqualValues(t, 2, count)

	list, err := f.stores.Invites.ListPending(ctx, f.projectID)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, "member", list[0].Role, "newest first")
	assert.Equal(t, "inviter@test.com", *list[0].CreatedByEmail)

	view, err := f.stores.Invites.Lookup(ctx, hashOf("token-a"))
	require.NoError(t, err)
	assert.Equal(t, "manager", view.Role)
	assert.Equal(t, email, *view.Email)
	assert.NotEmpty(t, view.ProjectName)

	_, err = f.stores.Invites.Lookup(ctx, hashOf("never-issued"))
	assert.ErrorIs(t, err, port.ErrNotFound)

	revoked, err := f.stores.Invites.Revoke(ctx, f.projectID, inv.ID)
	require.NoError(t, err)
	assert.Equal(t, inv.ID, revoked.ID)
	_, err = f.stores.Invites.Lookup(ctx, hashOf("token-a"))
	assert.ErrorIs(t, err, port.ErrNotFound, "a revoked link stops working")
	_, err = f.stores.Invites.Revoke(ctx, f.projectID, inv.ID)
	assert.ErrorIs(t, err, port.ErrNotFound, "revoking twice reports not found")
	_, err = f.stores.Invites.GetPending(ctx, f.projectID, inv.ID)
	assert.ErrorIs(t, err, port.ErrNotFound)
}

func TestInvites_ExpiredIsNotPending(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	f := newInviteFixture(t, repos)

	// Created in the past so the expiry check constraint holds.
	_, err := repos.pool.Exec(ctx, `INSERT INTO invites (token_hash, project_id, role, created_by, created_at, expires_at)
		VALUES ($1, $2, 'member', $3, NOW() - INTERVAL '2 days', NOW() - INTERVAL '1 day')`,
		hashOf("old"), f.projectID, f.inviter.ID)
	require.NoError(t, err)

	_, err = f.stores.Invites.Lookup(ctx, hashOf("old"))
	assert.ErrorIs(t, err, port.ErrNotFound)
	_, err = f.stores.Invites.AcceptAsUser(ctx, hashOf("old"), f.inviter.ID)
	assert.ErrorIs(t, err, port.ErrNotFound)
	count, err := f.stores.Invites.CountPending(ctx, f.projectID)
	require.NoError(t, err)
	assert.Zero(t, count)
}

func TestInvites_AcceptWithNewAccountIsSingleUse(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	f := newInviteFixture(t, repos)
	f.invite(t, "token-a", "manager", nil, inOneDay())
	name := "Newcomer"

	accepted, err := f.stores.Invites.AcceptWithNewAccount(ctx, hashOf("token-a"),
		port.InviteeAccount{Email: "newcomer@test.com", DisplayName: &name, PasswordHash: "$2a$10$hash"})
	require.NoError(t, err)
	assert.Equal(t, "newcomer@test.com", accepted.User.Email)
	assert.Equal(t, "member", accepted.User.Role, "an invite grants a project role, never a global one")
	assert.Equal(t, "manager", accepted.Role)
	assert.Equal(t, f.slug, accepted.ProjectSlug)

	member, err := f.stores.Projects.GetMember(ctx, f.projectID, accepted.User.ID)
	require.NoError(t, err)
	assert.Equal(t, "manager", member.Role)

	_, err = f.stores.Invites.AcceptWithNewAccount(ctx, hashOf("token-a"),
		port.InviteeAccount{Email: "second@test.com", PasswordHash: "$2a$10$hash"})
	assert.ErrorIs(t, err, port.ErrNotFound, "a used link is gone")
	_, err = f.stores.Users.GetByEmail(ctx, "second@test.com")
	assert.ErrorIs(t, err, port.ErrNotFound, "the second attempt created no account")
}

func TestInvites_FailedAcceptLeavesTheLinkUsable(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	f := newInviteFixture(t, repos)
	bound := "bound@test.com"
	f.invite(t, "token-bound", "member", &bound, inOneDay())
	f.invite(t, "token-open", "member", nil, inOneDay())
	taken := newUser(t, repos, "taken@test.com", "member")

	_, err := f.stores.Invites.AcceptWithNewAccount(ctx, hashOf("token-bound"),
		port.InviteeAccount{Email: "other@test.com", PasswordHash: "$2a$10$hash"})
	assert.ErrorIs(t, err, port.ErrInviteEmailMismatch)

	_, err = f.stores.Invites.AcceptWithNewAccount(ctx, hashOf("token-open"),
		port.InviteeAccount{Email: taken.Email, PasswordHash: "$2a$10$hash"})
	assert.ErrorIs(t, err, port.ErrEmailTaken)

	_, err = f.stores.Invites.AcceptAsUser(ctx, hashOf("token-bound"), taken.ID)
	assert.ErrorIs(t, err, port.ErrInviteEmailMismatch)

	for _, token := range []string{"token-bound", "token-open"} {
		_, err := f.stores.Invites.Lookup(ctx, hashOf(token))
		assert.NoError(t, err, "%s: the failed attempt rolled the claim back", token)
	}

	// The matching address still gets in, with different letter case.
	accepted, err := f.stores.Invites.AcceptWithNewAccount(ctx, hashOf("token-bound"),
		port.InviteeAccount{Email: "Bound@Test.com", PasswordHash: "$2a$10$hash"})
	require.NoError(t, err)
	assert.Equal(t, "member", accepted.Role)
}

func TestInvites_ExistingAccountKeepsAStrongerRole(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	f := newInviteFixture(t, repos)
	admin := newUser(t, repos, "admin@test.com", "member")
	manager := newUser(t, repos, "mgr@test.com", "member")
	newcomer := newUser(t, repos, "newcomer@test.com", "member")
	_, err := f.stores.Projects.UpsertMember(ctx, f.projectID, admin.ID, "admin")
	require.NoError(t, err)
	_, err = f.stores.Projects.UpsertMember(ctx, f.projectID, manager.ID, "manager")
	require.NoError(t, err)

	for i, tc := range []struct {
		user         port.User
		inviteRole   string
		expectedRole string
	}{
		{admin, "member", "admin"},
		{manager, "member", "manager"},
		{manager, "manager", "manager"},
		{newcomer, "member", "member"},
	} {
		token := "token-" + string(rune('a'+i))
		f.invite(t, token, tc.inviteRole, nil, inOneDay())
		accepted, err := f.stores.Invites.AcceptAsUser(ctx, hashOf(token), tc.user.ID)
		require.NoError(t, err)
		assert.Equal(t, tc.expectedRole, accepted.Role, "%s invited as %s", tc.user.Email, tc.inviteRole)
	}

	// An existing member can be raised by an invite.
	f.invite(t, "token-up", "manager", nil, inOneDay())
	accepted, err := f.stores.Invites.AcceptAsUser(ctx, hashOf("token-up"), newcomer.ID)
	require.NoError(t, err)
	assert.Equal(t, "manager", accepted.Role)
}

func TestInvites_RacingAcceptsUseTheLinkOnce(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	f := newInviteFixture(t, repos)
	f.invite(t, "token-race", "member", nil, inOneDay())

	const racers = 6
	results := make([]error, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, results[i] = f.stores.Invites.AcceptWithNewAccount(ctx, hashOf("token-race"),
				port.InviteeAccount{Email: "racer" + string(rune('a'+i)) + "@test.com", PasswordHash: "$2a$10$hash"})
		}()
	}
	close(start)
	wg.Wait()

	won := 0
	for _, err := range results {
		if err == nil {
			won++
		} else {
			assert.ErrorIs(t, err, port.ErrNotFound)
		}
	}
	assert.Equal(t, 1, won, "one request uses the link")
	members, err := f.stores.Projects.ListMembers(ctx, f.projectID)
	require.NoError(t, err)
	assert.Len(t, members, 1)
}

func TestInvites_DeletingTheProjectRemovesItsInvites(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	f := newInviteFixture(t, repos)
	f.invite(t, "token-a", "member", nil, inOneDay())

	_, err := repos.pool.Exec(ctx, "DELETE FROM projects WHERE id = $1", f.projectID)
	require.NoError(t, err)

	_, err = f.stores.Invites.Lookup(ctx, hashOf("token-a"))
	assert.ErrorIs(t, err, port.ErrNotFound)
}
