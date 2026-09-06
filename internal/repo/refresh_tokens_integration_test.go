//go:build integration

package repo

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/port"
)

// createTestRefreshUser creates a user who owns refresh tokens, with a
// unique email so tests never collide.
func createTestRefreshUser(t *testing.T, repos *Repos) sqlc.User {
	t.Helper()
	user, err := repos.Users.Create(context.Background(),
		"refresh-"+uuid.New().String()[:8]+"@test.com",
		pgtype.Text{Valid: false},
		pgtype.Text{Valid: true, String: "$2a$10$testhash"})
	require.NoError(t, err)
	return user
}

func createTestRefreshToken(t *testing.T, repos *Repos, userID pgtype.UUID, hash string) sqlc.RefreshToken {
	t.Helper()
	token, err := repos.RefreshTokens.Create(context.Background(), userID, hash, time.Now().Add(7*24*time.Hour))
	require.NoError(t, err)
	return token
}

// TestRefreshTokenRepo_RevokeIsCompareAndSwap pins the M3 SQL guard: the
// revoke must be an atomic compare-and-swap on the token row. Revoking an
// already-revoked token must match zero rows and surface as ErrNotFound
// (never silently succeed), so the use case can distinguish a clean rotation
// from reuse of a rotated token.
func TestRefreshTokenRepo_RevokeIsCompareAndSwap(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	user := createTestRefreshUser(t, repos)
	token := createTestRefreshToken(t, repos, user.ID, "hash-cas")

	// First revoke wins the row.
	revoked, err := repos.RefreshTokens.Revoke(ctx, token.ID)
	require.NoError(t, err)
	require.True(t, revoked.RevokedAt.Valid)

	// A second revoke of the same token is a zero-row update: pgx reports
	// no rows, which the adapter maps to port.ErrNotFound.
	_, err = repos.RefreshTokens.Revoke(ctx, token.ID)
	assert.ErrorIs(t, err, port.ErrNotFound,
		"revoking an already-revoked token must surface as not-found, not succeed")
}

// TestRefreshTokenRepo_ConcurrentRevokeOnlyOneWins drives the actual
// Postgres row lock: many goroutines race to revoke the same token row and
// exactly one may observe a successful revoke. This is the database-level
// half of the M3 atomicity guarantee (the use case half is unit-tested with
// a CAS-mocking store).
func TestRefreshTokenRepo_ConcurrentRevokeOnlyOneWins(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	user := createTestRefreshUser(t, repos)
	token := createTestRefreshToken(t, repos, user.ID, "hash-race")

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, errs[i] = repos.RefreshTokens.Revoke(ctx, token.ID)
		}(i)
	}
	wg.Wait()

	winners := 0
	for i, err := range errs {
		switch {
		case err == nil:
			winners++
		case errors.Is(err, port.ErrNotFound):
			// Expected for every loser.
		default:
			t.Fatalf("goroutine %d: unexpected revoke error: %v", i, err)
		}
	}
	assert.Equal(t, 1, winners, "exactly one concurrent revoke of the same token row may win")
}

// TestRefreshTokenRepo_RevokeAllForUser pins the reuse-detection fallback:
// revoking every active token for a user must retire the whole family and be
// idempotent on repeat.
func TestRefreshTokenRepo_RevokeAllForUser(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	user := createTestRefreshUser(t, repos)
	other := createTestRefreshUser(t, repos)
	t1 := createTestRefreshToken(t, repos, user.ID, "hash-family-1")
	t2 := createTestRefreshToken(t, repos, user.ID, "hash-family-2")
	// A token belonging to another user must survive the family revoke.
	otherToken := createTestRefreshToken(t, repos, other.ID, "hash-other")

	err := repos.RefreshTokens.RevokeAllForUser(ctx, user.ID)
	require.NoError(t, err)

	_, err = repos.RefreshTokens.Revoke(ctx, t1.ID)
	assert.ErrorIs(t, err, port.ErrNotFound, "first family token must be revoked")
	_, err = repos.RefreshTokens.Revoke(ctx, t2.ID)
	assert.ErrorIs(t, err, port.ErrNotFound, "second family token must be revoked")
	_, err = repos.RefreshTokens.Revoke(ctx, otherToken.ID)
	assert.NoError(t, err, "another user's token must be unaffected by the family revoke")

	// Idempotent: revoking an already-fully-revoked family is not an error.
	err = repos.RefreshTokens.RevokeAllForUser(ctx, user.ID)
	require.NoError(t, err)
}

// TestRefreshTokenRepo_RevokeExpiredTokenStillWins sanity-checks that the
// guarded revoke retires expired-but-unrevoked rows too (a token that passed
// the use-case expiry check races into revocation the same way).
func TestRefreshTokenRepo_RevokeExpiredTokenStillWins(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	user := createTestRefreshUser(t, repos)
	expiredToken, err := repos.RefreshTokens.Create(ctx, user.ID, "hash-expired", time.Now().Add(-time.Hour))
	require.NoError(t, err)

	revoked, err := repos.RefreshTokens.Revoke(ctx, expiredToken.ID)
	require.NoError(t, err)
	assert.True(t, revoked.RevokedAt.Valid)

	_, err = repos.RefreshTokens.Revoke(ctx, expiredToken.ID)
	assert.ErrorIs(t, err, port.ErrNotFound)
}
