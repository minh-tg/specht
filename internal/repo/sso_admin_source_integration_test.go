//go:build integration

package repo

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// ssoAdmin makes a member an admin the way an SSO login with an admin group does.
func ssoAdmin(t *testing.T, users port.UserStore, id string) port.User {
	t.Helper()
	u, err := users.SyncSSOAdmin(context.Background(), id, true)
	require.NoError(t, err)
	require.Equal(t, "admin", u.Role)
	require.Equal(t, port.AdminSourceSSO, u.AdminSource)
	return u
}

func TestSyncSSOAdmin_PromotesAMemberAsAnSSOAdmin(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	users := NewPortStores(repos.pool).Users
	member := newUser(t, repos, "member@test.com", "member")
	assert.Equal(t, port.AdminSourceManual, member.AdminSource, "the column defaults to manual")

	before, err := users.TokenVersion(ctx, member.ID)
	require.NoError(t, err)
	ssoAdmin(t, users, member.ID)
	after, err := users.TokenVersion(ctx, member.ID)
	require.NoError(t, err)
	assert.Equal(t, before+1, after, "a promotion starts a new token generation")
}

func TestSyncSSOAdmin_AManualAdminKeepsItsSource(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	users := NewPortStores(repos.pool).Users
	manual := newUser(t, repos, "manual@test.com", "admin")
	newUser(t, repos, "other@test.com", "admin")

	kept, err := users.SyncSSOAdmin(ctx, manual.ID, true)
	require.NoError(t, err)
	assert.Equal(t, port.AdminSourceManual, kept.AdminSource, "the group does not turn a manual grant into one the IdP can take back")

	kept, err = users.SyncSSOAdmin(ctx, manual.ID, false)
	require.NoError(t, err)
	assert.Equal(t, "admin", kept.Role, "a manual admin is never demoted by the IdP")
	assert.Equal(t, manual.TokenVersion, kept.TokenVersion)
}

func TestSyncSSOAdmin_DemotesAnSSOAdminAndEndsItsSessions(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	users := NewPortStores(repos.pool).Users
	newUser(t, repos, "manual@test.com", "admin")
	granted := ssoAdmin(t, users, newUser(t, repos, "sso@test.com", "member").ID)

	demoted, err := users.SyncSSOAdmin(ctx, granted.ID, false)
	require.NoError(t, err)
	assert.Equal(t, "member", demoted.Role)
	assert.Equal(t, granted.TokenVersion+1, demoted.TokenVersion, "open admin tokens stop working")

	again, err := users.SyncSSOAdmin(ctx, granted.ID, false)
	require.NoError(t, err)
	assert.Equal(t, demoted.TokenVersion, again.TokenVersion, "a member stays as is")
}

func TestSyncSSOAdmin_AHandGrantTakesTheRoleOverFromTheIdP(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	users := NewPortStores(repos.pool).Users
	newUser(t, repos, "manual@test.com", "admin")
	granted := ssoAdmin(t, users, newUser(t, repos, "sso@test.com", "member").ID)

	// An operator re-grants the role by hand. ChangeRole is the path of the
	// admin API and of grant-admin; it records the grant as manual.
	regranted, err := users.ChangeRole(ctx, granted.ID, "admin")
	require.NoError(t, err)
	assert.Equal(t, port.AdminSourceManual, regranted.AdminSource)
	assert.Equal(t, granted.TokenVersion, regranted.TokenVersion, "the role is the same, so no session has to end")

	kept, err := users.SyncSSOAdmin(ctx, granted.ID, false)
	require.NoError(t, err)
	assert.Equal(t, "admin", kept.Role)

	// ADMIN_EMAILS writes through SetRole, also a manual grant.
	other := ssoAdmin(t, users, newUser(t, repos, "listed@test.com", "member").ID)
	listed, err := users.SetRole(ctx, other.ID, "admin")
	require.NoError(t, err)
	assert.Equal(t, port.AdminSourceManual, listed.AdminSource)
}

func TestSyncSSOAdmin_TheLastActiveAdminKeepsTheRole(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	users := NewPortStores(repos.pool).Users
	only := ssoAdmin(t, users, newUser(t, repos, "only@test.com", "member").ID)

	kept, err := users.SyncSSOAdmin(ctx, only.ID, false)
	require.ErrorIs(t, err, port.ErrLastGlobalAdmin)
	assert.Equal(t, "admin", kept.Role, "the refusal returns the account as it is")

	still, err := users.GetByID(ctx, only.ID)
	require.NoError(t, err)
	assert.Equal(t, "admin", still.Role)
	assert.Equal(t, port.AdminSourceSSO, still.AdminSource)
	assert.Equal(t, only.TokenVersion, still.TokenVersion)
}

func TestSyncSSOAdmin_RefusesADeactivatedAccount(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	users := NewPortStores(repos.pool).Users
	newUser(t, repos, "manual@test.com", "admin")
	member := newUser(t, repos, "member@test.com", "member")
	_, err := users.SetDisabled(ctx, member.ID, true)
	require.NoError(t, err)

	_, err = users.SyncSSOAdmin(ctx, member.ID, true)
	require.ErrorIs(t, err, port.ErrAccountDeactivated)
	still, err := users.GetByID(ctx, member.ID)
	require.NoError(t, err)
	assert.Equal(t, "member", still.Role)
}

// Two SSO admins whose group is removed sign in at once while no one else is
// an admin: one of them keeps the role.
func TestSyncSSOAdmin_ConcurrentDemotionsLeaveAnAdmin(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	users := NewPortStores(repos.pool).Users
	a := ssoAdmin(t, users, newUser(t, repos, "a@test.com", "member").ID)
	b := ssoAdmin(t, users, newUser(t, repos, "b@test.com", "member").ID)

	var wg sync.WaitGroup
	results := make([]error, 2)
	for i, id := range []string{a.ID, b.ID} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, results[i] = users.SyncSSOAdmin(ctx, id, false)
		}()
	}
	wg.Wait()

	refused := 0
	for _, err := range results {
		if err != nil {
			require.ErrorIs(t, err, port.ErrLastGlobalAdmin)
			refused++
		}
	}
	assert.Equal(t, 1, refused)
	var admins int
	require.NoError(t, repos.pool.QueryRow(ctx, `SELECT count(*) FROM users WHERE role = 'admin' AND disabled_at IS NULL`).Scan(&admins))
	assert.Equal(t, 1, admins)
}
