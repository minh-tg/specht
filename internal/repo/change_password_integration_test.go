//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// ChangePasswordAndRevoke against the password login. A login holds a share
// lock on the account row from its guard check until its session commits; the
// change takes the row lock before it revokes, so it either follows a stored
// session and revokes it, or precedes the guard check and refuses the login.

const changePasswordGateKey = 7311

// installRefreshInsertGate makes every refresh_tokens INSERT wait for the
// shared advisory lock changePasswordGateKey. While a test holds it
// exclusively, a login stops after it passed its guard (and holds the account
// share lock) and before its token row exists.
func installRefreshInsertGate(t *testing.T, repos *Repos) {
	t.Helper()
	ctx := context.Background()
	_, err := repos.pool.Exec(ctx, `CREATE FUNCTION change_password_gate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_advisory_xact_lock_shared(7311); RETURN NEW; END $$`)
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, `CREATE TRIGGER change_password_gate BEFORE INSERT ON refresh_tokens
		FOR EACH ROW EXECUTE FUNCTION change_password_gate()`)
	require.NoError(t, err)
}

// holdRefreshInsertGate takes the gate exclusively and returns the release
// function, which is safe to call twice.
func holdRefreshInsertGate(t *testing.T, repos *Repos) (release func()) {
	t.Helper()
	ctx := context.Background()
	conn, err := repos.pool.Acquire(ctx)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SELECT pg_advisory_lock($1)", changePasswordGateKey)
	require.NoError(t, err)
	released := false
	return func() {
		if released {
			return
		}
		released = true
		_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", changePasswordGateKey)
		conn.Release()
	}
}

// waitForLockWaitersUnlessDone blocks until at least n backends wait on a lock, so the
// interleaving the test needs is reached before it moves on. It fails if done
// fires first, because the call under test should still be waiting.
func waitForLockWaitersUnlessDone(t *testing.T, repos *Repos, n int, done <-chan error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("the call finished before %d backends waited on a lock: %v", n, err)
		default:
		}
		var waiting int
		require.NoError(t, repos.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting))
		if waiting >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d lock waiters", n)
}

// changeAndRevoke is ChangePasswordAndRevoke for the tests that only look at
// its error.
func changeAndRevoke(ctx context.Context, users port.UserStore, userID, passwordHash, verifiedHash string) error {
	_, err := users.ChangePasswordAndRevoke(ctx, userID, passwordHash, verifiedHash)
	return err
}

func tokenVersionOf(t *testing.T, stores *port.Stores, userID string) int32 {
	t.Helper()
	v, err := stores.Users.TokenVersion(context.Background(), userID)
	require.NoError(t, err)
	return v
}

// The login passes its guard and parks right before its token row exists; the
// change starts and has to wait for the login's share lock; the login then
// commits. The session the login stored must not outlive the change.
func TestChangePasswordRevokesALoginThatWasParkedBeforeItsSessionCommitted(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "change-parked-login@test.com", "member")
	installRefreshInsertGate(t, repos)
	release := holdRefreshInsertGate(t, repos)
	defer release()

	loginDone := make(chan error, 1)
	go func() {
		_, err := loginAttempt(t, stores, user)
		loginDone <- err
	}()
	waitForLockWaitersUnlessDone(t, repos, 1, loginDone)

	changeDone := make(chan error, 1)
	go func() {
		changeDone <- changeAndRevoke(ctx, stores.Users, user.ID, "$2a$10$changed", user.PasswordHash)
	}()
	waitForLockWaitersUnlessDone(t, repos, 2, changeDone)

	release()
	require.NoError(t, <-loginDone, "the login passed its guard before the change started")
	require.NoError(t, <-changeDone)

	assert.Zero(t, liveRefreshTokens(t, repos, user.ID), "the session the login stored under its lock is revoked by the change")
	assert.Equal(t, user.TokenVersion+1, tokenVersionOf(t, stores, user.ID))
}

// The same order without the gate: the login holds its share lock while the
// change waits for it.
func TestChangePasswordWaitsForALoginHoldingItsShareLock(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "change-held-login@test.com", "member")

	tx, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "SELECT 1 FROM users WHERE id = $1 FOR SHARE", user.ID)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO refresh_tokens (user_id, token_hash, expires_at, family_id, family_started_at)
		VALUES ($1, 'held-login', now() + interval '1 hour', gen_random_uuid(), now())`, user.ID)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- changeAndRevoke(ctx, stores.Users, user.ID, "$2a$10$changed", user.PasswordHash)
	}()
	mustBlock(t, done, "the password change")
	require.NoError(t, tx.Commit(ctx))
	require.NoError(t, <-done)

	assert.Zero(t, liveRefreshTokens(t, repos, user.ID), "the session stored under the login's lock survives the password change")
}

// A login that read the account before the change and reaches the lock after
// it is refused, and no change leaves a session behind.
func TestLoginAfterAPasswordChangeIsRefused(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "change-then-login@test.com", "member")

	require.NoError(t, changeAndRevoke(ctx, stores.Users, user.ID, "$2a$10$changed", user.PasswordHash))

	_, err := loginAttempt(t, stores, user)
	require.ErrorIs(t, err, port.ErrLoginStale)
	assert.Zero(t, liveRefreshTokens(t, repos, user.ID))
}

func TestChangePasswordAndRevokeWritesTheHashTheGenerationAndTheRevokes(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	f := newResetFixture(t, repos, "change-all@test.com")
	other := newUser(t, repos, "change-other@test.com", "member")
	_, err := loginAttempt(t, f.stores, f.user)
	require.NoError(t, err)
	_, err = loginAttempt(t, f.stores, other)
	require.NoError(t, err)
	require.Equal(t, 1, f.pendingLinks(t))
	before := tokenVersionOf(t, f.stores, f.user.ID)

	version, err := f.stores.Users.ChangePasswordAndRevoke(ctx, f.user.ID, "$2a$10$changed", f.user.PasswordHash)
	require.NoError(t, err)

	assert.Equal(t, before+1, version, "the call returns the generation it started")
	require.NotNil(t, f.passwordHash(t))
	assert.Equal(t, "$2a$10$changed", *f.passwordHash(t))
	assert.Equal(t, before+1, tokenVersionOf(t, f.stores, f.user.ID), "a successful change starts a new token generation")
	assert.Zero(t, liveRefreshTokens(t, repos, f.user.ID))
	assert.Zero(t, f.pendingLinks(t), "a reset link issued before the change would overwrite the new password")
	assert.Equal(t, 1, liveRefreshTokens(t, repos, other.ID), "another account keeps its sessions")
	assert.Equal(t, int32(0), tokenVersionOf(t, f.stores, other.ID))
}

func TestChangePasswordAndRevokeWritesNothingWhenTheVerifiedHashIsStale(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "change-stale@test.com", "member")
	_, err := loginAttempt(t, stores, user)
	require.NoError(t, err)

	err = changeAndRevoke(ctx, stores.Users, user.ID, "$2a$10$changed", "$2a$10$not-the-stored-hash")
	require.ErrorIs(t, err, port.ErrPasswordStale)

	got, err := stores.Users.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.PasswordHash, got.PasswordHash)
	assert.Equal(t, user.TokenVersion, got.TokenVersion)
	assert.Equal(t, 1, liveRefreshTokens(t, repos, user.ID), "a refused change revokes nothing")
}

// The recovery path has no password to verify, so an empty verifiedHash skips
// the compare and also works for an account that has no password yet.
func TestChangePasswordAndRevokeWithoutAVerifiedHashSetsAPasswordOnAnyAccount(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "change-recovery@test.com", "member")
	require.NoError(t, stores.Users.ClearPassword(ctx, user.ID))

	require.NoError(t, changeAndRevoke(ctx, stores.Users, user.ID, "$2a$10$recovered", ""))

	got, err := stores.Users.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, "$2a$10$recovered", got.PasswordHash)

	err = changeAndRevoke(ctx, stores.Users, uuid.NewString(), "$2a$10$recovered", "")
	assert.ErrorIs(t, err, port.ErrNotFound)
}

// An SSO link clears the password. A change that verified the old hash before
// the link and reaches the lock after it must not give the account a password
// again.
func TestChangePasswordDuringAnOpenSSOLinkLeavesTheAccountPasswordless(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "change-sso@test.com", "member")
	tx := openSSOLinkTx(t, repos, user.ID)
	defer func() { _ = tx.Rollback(ctx) }()

	done := make(chan error, 1)
	go func() {
		done <- changeAndRevoke(ctx, stores.Users, user.ID, "$2a$10$changed", user.PasswordHash)
	}()
	mustBlock(t, done, "the password change")
	require.NoError(t, tx.Commit(ctx))

	require.ErrorIs(t, <-done, port.ErrPasswordStale)
	var hash *string
	require.NoError(t, repos.pool.QueryRow(ctx, "SELECT password_hash FROM users WHERE id = $1", user.ID).Scan(&hash))
	assert.Nil(t, hash, "the linked account stays password-less")
}
