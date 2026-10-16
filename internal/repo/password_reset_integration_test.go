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

// resetFixture is an account with a password and one pending reset link.
type resetFixture struct {
	repos  *Repos
	stores *port.Stores
	user   port.User
	token  string
}

func newResetFixture(t *testing.T, repos *Repos, email string) resetFixture {
	t.Helper()
	stores := NewPortStores(repos.pool)
	admin := newUser(t, repos, "admin-"+uuid.NewString()+"@test.com", "admin")
	user := newUser(t, repos, email, "member")
	token := "tok-" + uuid.NewString()
	require.NoError(t, stores.PasswordReset.Create(context.Background(), port.NewPasswordReset{
		TokenHash: token,
		UserID:    user.ID,
		CreatedBy: admin.ID,
		ExpiresAt: time.Now().Add(time.Hour),
	}))
	return resetFixture{repos: repos, stores: stores, user: user, token: token}
}

func (f resetFixture) redeem(t *testing.T) error {
	t.Helper()
	_, err := f.stores.PasswordReset.Redeem(context.Background(), f.token, "$2a$10$new-hash")
	return err
}

func (f resetFixture) passwordHash(t *testing.T) *string {
	t.Helper()
	var hash *string
	require.NoError(t, f.repos.pool.QueryRow(context.Background(),
		"SELECT password_hash FROM users WHERE id = $1", f.user.ID).Scan(&hash))
	return hash
}

// pendingLinks counts the account's links that can still be redeemed.
func (f resetFixture) pendingLinks(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, f.repos.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM password_resets
		 WHERE user_id = $1 AND used_at IS NULL AND revoked_at IS NULL`, f.user.ID).Scan(&n))
	return n
}

func TestRedeemRefusesADeactivatedAccount(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	f := newResetFixture(t, repos, "gone@test.com")
	// Written directly so the link stays pending: this pins the redeem side
	// alone, whatever the deactivation path does to the link.
	_, err := repos.pool.Exec(context.Background(), "UPDATE users SET disabled_at = now() WHERE id = $1", f.user.ID)
	require.NoError(t, err)

	require.ErrorIs(t, f.redeem(t), port.ErrNotFound, "a deactivated account answers like an expired link")

	require.NotNil(t, f.passwordHash(t))
	assert.Equal(t, "$2a$10$hash", *f.passwordHash(t), "the password is untouched")
	assert.Equal(t, 1, f.pendingLinks(t), "a refused redeem spends nothing")
}

func TestRedeemRefusesAnAccountThatSignsInThroughSSO(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	f := newResetFixture(t, repos, "sso@test.com")
	_, err := repos.pool.Exec(context.Background(), "UPDATE users SET password_hash = NULL WHERE id = $1", f.user.ID)
	require.NoError(t, err)

	require.ErrorIs(t, f.redeem(t), port.ErrNotFound)

	assert.Nil(t, f.passwordHash(t), "a redeem never gives a provider-owned account a password")
}

// A deactivation that has updated the account row but not committed yet must
// hold the redeem back: after the commit the redeem sees the account as
// deactivated and refuses, instead of setting a password on it.
func TestRedeemWaitsForAnInFlightDeactivation(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	f := newResetFixture(t, repos, "racing@test.com")

	tx, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "UPDATE users SET disabled_at = now() WHERE id = $1", f.user.ID)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- f.redeem(t) }()

	select {
	case err := <-done:
		t.Fatalf("redeem finished while the deactivation was still open: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	require.NoError(t, tx.Commit(ctx))

	select {
	case err := <-done:
		require.ErrorIs(t, err, port.ErrNotFound)
	case <-time.After(5 * time.Second):
		t.Fatal("redeem never finished after the deactivation committed")
	}
	assert.Equal(t, "$2a$10$hash", *f.passwordHash(t))
}
