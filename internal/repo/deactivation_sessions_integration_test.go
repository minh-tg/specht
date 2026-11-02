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

// Deactivation ends the account's refresh tokens in its own transaction, and
// reactivation starts a new token generation, so a session from before the
// deactivation never works again.
func TestDeactivateRevokesRefreshTokensInTheSameTransaction(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "deactivation-admin@test.com", "admin")
	user := newUser(t, repos, "deactivation-user@test.com", "member")

	old, err := stores.RefreshTokens.Create(ctx, port.NewRefreshToken{
		UserID: user.ID, TokenHash: "old-" + uuid.NewString(), ExpiresAt: time.Now().Add(time.Hour),
		FamilyID: uuid.NewString(), FamilyStartedAt: time.Now(),
	})
	require.NoError(t, err)

	_, _, err = stores.Users.Deactivate(ctx, user.ID, false)
	require.NoError(t, err)
	assert.Equal(t, 0, liveRefreshTokens(t, repos, user.ID), "the deactivation commit leaves no live refresh token")

	_, err = stores.Users.SetDisabled(ctx, user.ID, false)
	require.NoError(t, err)
	current, err := stores.Users.TokenVersion(ctx, user.ID)
	require.NoError(t, err)
	err = stores.RefreshTokens.Rotate(ctx, old.ID, port.NewRefreshToken{
		UserID: user.ID, TokenHash: "new-" + uuid.NewString(), ExpiresAt: time.Now().Add(time.Hour),
		FamilyID: old.FamilyID, FamilyStartedAt: old.FamilyStartedAt,
	}, current)
	assert.Error(t, err, "a token from before the deactivation does not rotate after reactivation")
}

func TestReactivateStartsANewTokenGenerationOnlyForADeactivatedAccount(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "generation-admin@test.com", "admin")
	user := newUser(t, repos, "generation-user@test.com", "member")

	before, err := stores.Users.TokenVersion(ctx, user.ID)
	require.NoError(t, err)
	_, err = stores.Users.SetDisabled(ctx, user.ID, false)
	require.NoError(t, err)
	same, err := stores.Users.TokenVersion(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, before, same, "reactivating an active account keeps its sessions")

	_, _, err = stores.Users.Deactivate(ctx, user.ID, false)
	require.NoError(t, err)
	disabled, err := stores.Users.TokenVersion(ctx, user.ID)
	require.NoError(t, err)
	_, err = stores.Users.SetDisabled(ctx, user.ID, false)
	require.NoError(t, err)
	reactivated, err := stores.Users.TokenVersion(ctx, user.ID)
	require.NoError(t, err)
	assert.Greater(t, disabled, before)
	assert.Greater(t, reactivated, disabled, "reactivation bumps the generation again")
}
