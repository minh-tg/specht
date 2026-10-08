//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSOCodes_CreateAndConsume(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	store := &pgSSOCodePort{q: sqlc.New(repos.pool)}

	userID := newTestUserID(t, repos)
	const (
		codeHash = "hash123"
		email    = "alice@example.com"
		role     = "member"
	)

	// Create code with future expiry
	expiresAt := time.Now().Add(1 * time.Minute)
	err := store.Create(ctx, codeHash, userID, email, role, expiresAt)
	require.NoError(t, err)

	// First consume succeeds
	consumed, err := store.Consume(ctx, codeHash, time.Now())
	require.NoError(t, err)
	assert.Equal(t, codeHash, consumed.CodeHash)
	assert.Equal(t, userID, consumed.UserID)
	assert.Equal(t, email, consumed.Email)
	assert.Equal(t, role, consumed.Role)

	// Second consume fails (single-use)
	_, err = store.Consume(ctx, codeHash, time.Now())
	assert.ErrorIs(t, err, port.ErrNotFound)
}

func TestSSOCodes_ExpiredCodeNotFound(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	store := &pgSSOCodePort{q: sqlc.New(repos.pool)}

	userID := newTestUserID(t, repos)
	const codeHash = "expired-hash"

	// Create code expired in the past
	expiresAt := time.Now().Add(-1 * time.Minute)
	err := store.Create(ctx, codeHash, userID, "alice@example.com", "member", expiresAt)
	require.NoError(t, err)

	// Consume fails because now is past expiresAt
	_, err = store.Consume(ctx, codeHash, time.Now())
	assert.ErrorIs(t, err, port.ErrNotFound)
}

func TestSSOCodes_CascadeDeleteOnUser(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	store := &pgSSOCodePort{q: sqlc.New(repos.pool)}

	userID := newTestUserID(t, repos)
	const codeHash = "user-delete-hash"

	err := store.Create(ctx, codeHash, userID, "alice@example.com", "member", time.Now().Add(1*time.Minute))
	require.NoError(t, err)

	// Delete user
	_, err = repos.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, uuid.MustParse(userID))
	require.NoError(t, err)

	// Code was removed by ON DELETE CASCADE
	_, err = store.Consume(ctx, codeHash, time.Now())
	assert.ErrorIs(t, err, port.ErrNotFound)
}
