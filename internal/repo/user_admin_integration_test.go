//go:build integration

package repo

import (
	"context"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// NewPortStoresUsers returns the user store over the repos' pool.
func NewPortStoresUsers(repos *Repos) port.UserStore {
	return NewPortStores(repos.pool).Users
}

func newUser(t *testing.T, repos *Repos, email, role string) port.User {
	t.Helper()
	ctx := context.Background()
	row, err := repos.Users.Create(ctx, email, pgtype.Text{Valid: false}, pgtype.Text{String: "$2a$10$hash", Valid: true})
	require.NoError(t, err)
	if role == "member" {
		return userToPort(row)
	}
	promoted, err := NewPortStoresUsers(repos).SetRole(ctx, toUUID(row.ID), role)
	require.NoError(t, err)
	return promoted
}

func TestUserRoleChangeAndDeactivation(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	admin := newUser(t, repos, "admin@test.com", "admin")
	member := newUser(t, repos, "member@test.com", "member")

	before, err := stores.Users.TokenVersion(ctx, member.ID)
	require.NoError(t, err)

	promoted, err := stores.Users.ChangeRole(ctx, member.ID, "admin")
	require.NoError(t, err)
	assert.Equal(t, "admin", promoted.Role)
	after, err := stores.Users.TokenVersion(ctx, member.ID)
	require.NoError(t, err)
	assert.Equal(t, before+1, after, "a role change starts a new token generation so open sessions pick it up")

	disabled, err := stores.Users.SetDisabled(ctx, member.ID, true)
	require.NoError(t, err)
	require.NotNil(t, disabled.DisabledAt)
	gen, err := stores.Users.TokenVersion(ctx, member.ID)
	require.NoError(t, err)
	assert.Equal(t, after+1, gen, "deactivation ends open sessions")

	again, err := stores.Users.SetDisabled(ctx, member.ID, true)
	require.NoError(t, err, "deactivating twice is harmless")
	assert.Equal(t, disabled.DisabledAt.Unix(), again.DisabledAt.Unix(), "the original time is kept")

	enabled, err := stores.Users.SetDisabled(ctx, member.ID, false)
	require.NoError(t, err)
	assert.Nil(t, enabled.DisabledAt)
	regen, err := stores.Users.TokenVersion(ctx, member.ID)
	require.NoError(t, err)
	assert.Equal(t, gen+1, regen, "the generation counts the second deactivation but not the reactivation")
	_ = admin
}

func TestLastGlobalAdminCannotBeDemotedOrDeactivated(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	only := newUser(t, repos, "only@test.com", "admin")

	_, err := stores.Users.ChangeRole(ctx, only.ID, "member")
	require.ErrorIs(t, err, port.ErrLastGlobalAdmin)
	_, err = stores.Users.SetDisabled(ctx, only.ID, true)
	require.ErrorIs(t, err, port.ErrLastGlobalAdmin)

	still, err := stores.Users.GetByID(ctx, only.ID)
	require.NoError(t, err)
	assert.Equal(t, "admin", still.Role)
	assert.Nil(t, still.DisabledAt)

	second := newUser(t, repos, "second@test.com", "admin")
	_, err = stores.Users.ChangeRole(ctx, only.ID, "member")
	require.NoError(t, err, "with a second active admin the first can step down")

	_, err = stores.Users.SetDisabled(ctx, second.ID, true)
	require.ErrorIs(t, err, port.ErrLastGlobalAdmin, "the remaining admin is now the last one")

	_, err = stores.Users.ChangeRole(ctx, "00000000-0000-0000-0000-00000000dead", "admin")
	require.ErrorIs(t, err, port.ErrNotFound)
}

func TestDeactivatedAdminDoesNotCountAsAnActiveAdmin(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	first := newUser(t, repos, "first@test.com", "admin")
	second := newUser(t, repos, "second@test.com", "admin")

	_, err := stores.Users.SetDisabled(ctx, second.ID, true)
	require.NoError(t, err)

	_, err = stores.Users.SetDisabled(ctx, first.ID, true)
	require.ErrorIs(t, err, port.ErrLastGlobalAdmin, "a deactivated admin cannot stand in for the last active one")
}

// Two admins stepping down at once must not both succeed.
func TestLastAdminGuardHoldsUnderConcurrency(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	a := newUser(t, repos, "a@test.com", "admin")
	b := newUser(t, repos, "b@test.com", "admin")

	var wg sync.WaitGroup
	results := make([]error, 2)
	for i, id := range []string{a.ID, b.ID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = stores.Users.ChangeRole(ctx, id, "member")
		}()
	}
	wg.Wait()

	succeeded := 0
	for _, err := range results {
		if err == nil {
			succeeded++
		} else {
			assert.ErrorIs(t, err, port.ErrLastGlobalAdmin)
		}
	}
	assert.Equal(t, 1, succeeded, "exactly one of two concurrent demotions goes through")

	var admins int
	require.NoError(t, repos.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = 'admin'`).Scan(&admins))
	assert.Equal(t, 1, admins, "an admin is always left")
}

// The seeded system account acts for things with no person behind them, so the admin totals do not
// count it as one.
func TestAdminOverviewDoesNotCountTheSystemAccount(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)

	empty, err := stores.Admin.Overview(ctx)
	require.NoError(t, err)
	assert.Zero(t, empty.UserCount, "only the seeded system account exists")

	newUser(t, repos, "ada@test.com", "admin")
	newUser(t, repos, "lena@test.com", "member")
	counted, err := stores.Admin.Overview(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 2, counted.UserCount)
}
