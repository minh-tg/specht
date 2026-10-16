//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// Credential lifecycle races. Each
// test asserts the secure outcome.

// openSSOLinkTx starts the statements an SSO link runs first (the same order as
// LinkRevokingKeys) and leaves the transaction open.
func openSSOLinkTx(t *testing.T, repos *Repos, userID string) pgx.Tx {
	t.Helper()
	ctx := context.Background()
	tx, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	for _, stmt := range []string{
		"UPDATE users SET password_hash = NULL, updated_at = now() WHERE id = $1",
		"UPDATE users SET token_version = token_version + 1 WHERE id = $1",
		"UPDATE refresh_tokens SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL",
		"UPDATE password_resets SET revoked_at = now() WHERE user_id = $1 AND used_at IS NULL AND revoked_at IS NULL",
		"UPDATE api_keys SET revoked_at = now() WHERE created_by = $1 AND revoked_at IS NULL",
		"UPDATE users SET email_proven = TRUE WHERE id = $1",
	} {
		_, err := tx.Exec(ctx, stmt, userID)
		require.NoError(t, err, stmt)
	}
	return tx
}

func mustBlock(t *testing.T, done <-chan error, what string) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("%s finished while the other transaction was open: %v", what, err)
	case <-time.After(400 * time.Millisecond):
	}
}

// Redeem while an SSO link is in flight. Discriminates LockResettableUser: the
// EXISTS in ClaimPasswordReset alone reads the pre-link row.
func TestRedeemDuringAnOpenSSOLinkSetsNoPassword(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	f := newResetFixture(t, repos, "race-redeem-link@test.com")
	tx := openSSOLinkTx(t, repos, f.user.ID)
	defer func() { _ = tx.Rollback(context.Background()) }()

	done := make(chan error, 1)
	go func() { done <- f.redeem(t) }()
	mustBlock(t, done, "the redeem")
	require.NoError(t, tx.Commit(context.Background()))

	err := <-done
	require.ErrorIs(t, err, port.ErrNotFound)
	assert.Nil(t, f.passwordHash(t), "the linked account must stay password-less")
}

// Redeem while a password change is in flight: the change retires the link.
func TestRedeemDuringAnOpenPasswordChangeLosesToTheChange(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	f := newResetFixture(t, repos, "race-redeem-change@test.com")
	tx, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "UPDATE users SET password_hash = '$2a$10$changed' WHERE id = $1", f.user.ID)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, "UPDATE password_resets SET revoked_at = now() WHERE user_id = $1 AND used_at IS NULL AND revoked_at IS NULL", f.user.ID)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- f.redeem(t) }()
	mustBlock(t, done, "the redeem")
	require.NoError(t, tx.Commit(ctx))

	require.ErrorIs(t, <-done, port.ErrNotFound)
	require.NotNil(t, f.passwordHash(t))
	assert.Equal(t, "$2a$10$changed", *f.passwordHash(t))
}

// Issuing a link while an SSO link is in flight: the link must not be stored.
func TestIssuingALinkDuringAnOpenSSOLinkStoresNothing(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	admin := newUser(t, repos, "race-admin-"+uuid.NewString()+"@test.com", "admin")
	user := newUser(t, repos, "race-issue-link@test.com", "member")
	tx := openSSOLinkTx(t, repos, user.ID)
	defer func() { _ = tx.Rollback(ctx) }()

	done := make(chan error, 1)
	go func() {
		done <- stores.PasswordReset.Create(ctx, port.NewPasswordReset{
			TokenHash: "race-" + uuid.NewString(), UserID: user.ID, CreatedBy: admin.ID, ExpiresAt: time.Now().Add(time.Hour),
		})
	}()
	mustBlock(t, done, "issuing the link")
	require.NoError(t, tx.Commit(ctx))

	require.ErrorIs(t, <-done, port.ErrNotFound)
	var n int
	require.NoError(t, repos.pool.QueryRow(ctx,
		"SELECT count(*) FROM password_resets WHERE user_id = $1 AND used_at IS NULL AND revoked_at IS NULL", user.ID).Scan(&n))
	assert.Zero(t, n)
}

// loginAttempt is a password login that read the account (hash and token
// generation) before its password check and now stores its session.
func loginAttempt(t *testing.T, stores *port.Stores, user port.User) (int32, error) {
	t.Helper()
	return stores.RefreshTokens.CreateForLogin(context.Background(), port.NewRefreshToken{
		UserID:          user.ID,
		TokenHash:       "login-" + uuid.NewString(),
		ExpiresAt:       time.Now().Add(time.Hour),
		FamilyID:        uuid.NewString(),
		FamilyStartedAt: time.Now(),
	}, port.LoginGuard{PasswordHash: user.PasswordHash, TokenVersion: user.TokenVersion})
}

func liveRefreshTokens(t *testing.T, repos *Repos, userID string) int {
	t.Helper()
	var n int
	require.NoError(t, repos.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL", userID).Scan(&n))
	return n
}

// A login whose password check ended after an SSO link committed gets no
// session: the link cleared the password and started a new generation.
func TestLoginDuringAnOpenSSOLinkGetsNoSession(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "race-login-link@test.com", "member")
	tx := openSSOLinkTx(t, repos, user.ID)
	defer func() { _ = tx.Rollback(context.Background()) }()

	done := make(chan error, 1)
	go func() {
		_, err := loginAttempt(t, stores, user)
		done <- err
	}()
	mustBlock(t, done, "the login")
	require.NoError(t, tx.Commit(context.Background()))

	require.ErrorIs(t, <-done, port.ErrLoginStale)
	assert.Zero(t, liveRefreshTokens(t, repos, user.ID))
}

// A login that straddles a deactivation gets no session, whether or not the
// deactivation started a new generation.
func TestLoginDuringAnOpenDeactivationGetsNoSession(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "race-login-deact@test.com", "member")
	tx, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "UPDATE users SET disabled_at = now() WHERE id = $1", user.ID)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := loginAttempt(t, stores, user)
		done <- err
	}()
	mustBlock(t, done, "the login")
	require.NoError(t, tx.Commit(ctx))

	require.ErrorIs(t, <-done, port.ErrLoginStale)
	assert.Zero(t, liveRefreshTokens(t, repos, user.ID))
}

// A login that verified the old password after the password changed gets no
// session.
func TestLoginDuringAnOpenPasswordChangeGetsNoSession(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "race-login-change@test.com", "member")
	tx, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "UPDATE users SET password_hash = '$2a$10$changed' WHERE id = $1", user.ID)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := loginAttempt(t, stores, user)
		done <- err
	}()
	mustBlock(t, done, "the login")
	require.NoError(t, tx.Commit(ctx))

	require.ErrorIs(t, <-done, port.ErrLoginStale)
	assert.Zero(t, liveRefreshTokens(t, repos, user.ID))
}

// An unchanged account gets its session and the generation read under the lock.
func TestLoginOnAnUnchangedAccountStoresTheSession(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "race-login-ok@test.com", "member")

	version, err := loginAttempt(t, stores, user)
	require.NoError(t, err)
	assert.Equal(t, user.TokenVersion, version)
	assert.Equal(t, 1, liveRefreshTokens(t, repos, user.ID))
}

// A login for an account that no longer exists gets the stale answer.
func TestLoginForAMissingAccountIsStale(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	stores := NewPortStores(repos.pool)

	_, err := loginAttempt(t, stores, port.User{ID: uuid.NewString(), PasswordHash: "x"})
	require.ErrorIs(t, err, port.ErrLoginStale)
}

// A new token generation alone (a role change, a session reset) refuses the
// login even when the hash and the active state are unchanged.
func TestLoginAfterAGenerationBumpGetsNoSession(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	user := newUser(t, repos, "race-login-bump@test.com", "member")
	require.NoError(t, stores.Users.BumpTokenVersion(ctx, user.ID))

	_, err := loginAttempt(t, stores, user)
	require.ErrorIs(t, err, port.ErrLoginStale)
	assert.Zero(t, liveRefreshTokens(t, repos, user.ID))
}

// A key insert that passed authentication before the SSO link committed. The
// creator stays active, so LockKeyCreator lets it through after the link.
func TestKeyInsertDuringAnOpenSSOLinkLeavesNoLiveKey(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "race-admin@test.com", "admin")
	squat := newUser(t, repos, "race-key-link@test.com", "member")
	project := createTestProject(t, repos)
	tx := openSSOLinkTx(t, repos, squat.ID)
	defer func() { _ = tx.Rollback(ctx) }()

	done := make(chan error, 1)
	go func() {
		// The request authenticated with the generation from before the link.
		in := newKeyInput(toUUID(project.ID), squat.ID, "race-hash-link")
		in.CreatorTokenVersion = &squat.TokenVersion
		_, err := stores.APIKeys.Create(ctx, in)
		done <- err
	}()
	mustBlock(t, done, "the key insert")
	require.NoError(t, tx.Commit(ctx))
	require.ErrorIs(t, <-done, port.ErrCreatorInactive)

	var live int
	require.NoError(t, repos.pool.QueryRow(ctx,
		"SELECT count(*) FROM api_keys WHERE created_by = $1 AND revoked_at IS NULL", squat.ID).Scan(&live))
	assert.Zero(t, live, "a key the squatter requested before the link is live on the linked account")
}

// The key insert compares the creator's generation with the one the request
// authenticated with: a different generation is refused, a matching one or none
// is stored.
func TestKeyInsertComparesTheCreatorGeneration(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "race-key-gen-admin@test.com", "admin")
	creator := newUser(t, repos, "race-key-gen@test.com", "member")
	project := createTestProject(t, repos)
	require.NoError(t, stores.Users.BumpTokenVersion(ctx, creator.ID))

	stale := creator.TokenVersion
	in := newKeyInput(toUUID(project.ID), creator.ID, "race-hash-stale")
	in.CreatorTokenVersion = &stale
	_, err := stores.APIKeys.Create(ctx, in)
	require.ErrorIs(t, err, port.ErrCreatorInactive)
	assert.Zero(t, keyCount(t, repos, "race-hash-stale"))

	current := creator.TokenVersion + 1
	in = newKeyInput(toUUID(project.ID), creator.ID, "race-hash-current")
	in.CreatorTokenVersion = &current
	_, err = stores.APIKeys.Create(ctx, in)
	require.NoError(t, err)

	_, err = stores.APIKeys.Create(ctx, newKeyInput(toUUID(project.ID), creator.ID, "race-hash-none"))
	require.NoError(t, err)
}
