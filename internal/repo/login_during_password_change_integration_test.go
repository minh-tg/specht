//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ChangePassword revokes the account's refresh tokens and then writes the new
// hash with SetPassword, as two statements. The login's FOR SHARE lock in
// CreateForLogin only serializes against the users row update, so a login whose
// session insert commits between the two sees the old hash, passes its guard,
// and keeps a refresh token that the password change never revokes. Refresh
// does not compare token generations, so that token would keep minting access
// tokens after the change. No session may survive.
func TestPasswordChangeLeavesNoSessionFromALoginBetweenItsRevokeAndSet(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "login-change@test.com", "member")

	// ChangePassword, step 1: RevokeAllForUser.
	require.NoError(t, stores.RefreshTokens.RevokeAllForUser(ctx, user.ID))
	// A login that verified the old password stores its session now.
	_, err := loginAttempt(t, stores, user)
	require.NoError(t, err, "the login's guard sees the old hash and generation")
	// ChangePassword, step 2: SetPassword (new hash, new generation).
	require.NoError(t, stores.Users.SetPassword(ctx, user.ID, "$2a$10$new-hash"))

	assert.Zero(t, liveRefreshTokens(t, repos, user.ID),
		"a session from a login with the old password outlives the password change")
}

// The same interleaving with real concurrency: the login holds its share lock
// while SetPassword waits for it, which is the order the comment on
// LockUserForLogin says ends the session "with the rest".
func TestPasswordChangeLeavesNoSessionFromALoginHoldingItsLock(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "login-change2@test.com", "member")

	require.NoError(t, stores.RefreshTokens.RevokeAllForUser(ctx, user.ID))
	tx, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "SELECT 1 FROM users WHERE id = $1 FOR SHARE", user.ID)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, family_id, family_started_at)
		VALUES ($1, 'held-login', now() + interval '1 hour', gen_random_uuid(), now())`, user.ID)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- stores.Users.SetPassword(ctx, user.ID, "$2a$10$new-hash") }()
	mustBlock(t, done, "SetPassword")
	require.NoError(t, tx.Commit(ctx))
	require.NoError(t, <-done)

	assert.Zero(t, liveRefreshTokens(t, repos, user.ID),
		"the session stored under the login's lock survives the password change")
}
