//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUsers_BumpTokenVersionAdvancesTheGeneration(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	users := &pgUserPort{q: sqlc.New(repos.pool)}

	created, err := users.Create(ctx, "carol@example.com", nil, nil)
	require.NoError(t, err)
	other, err := users.Create(ctx, "dan@example.com", nil, nil)
	require.NoError(t, err)

	version, err := users.TokenVersion(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), version)

	require.NoError(t, users.BumpTokenVersion(ctx, created.ID))
	require.NoError(t, users.BumpTokenVersion(ctx, created.ID))

	version, err = users.TokenVersion(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, int32(2), version)

	version, err = users.TokenVersion(ctx, other.ID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), version, "other accounts keep their generation")
}

func TestUsers_SetPasswordReplacesTheHashAndStartsANewGeneration(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	users := &pgUserPort{q: sqlc.New(repos.pool)}

	oldHash := "old-hash"
	name := "Eve"
	created, err := users.Create(ctx, "eve@example.com", &name, &oldHash)
	require.NoError(t, err)
	other, err := users.Create(ctx, "fay@example.com", nil, &oldHash)
	require.NoError(t, err)

	require.NoError(t, users.SetPassword(ctx, created.ID, "new-hash"))

	got, err := users.GetByID(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, "new-hash", got.PasswordHash)
	assert.Equal(t, "eve@example.com", got.Email, "nothing else changes")
	require.NotNil(t, got.DisplayName)
	assert.Equal(t, "Eve", *got.DisplayName)

	version, err := users.TokenVersion(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), version, "the write starts a new token generation in the same statement")

	untouched, err := users.GetByID(ctx, other.ID)
	require.NoError(t, err)
	assert.Equal(t, "old-hash", untouched.PasswordHash, "other accounts keep their password")
	otherVersion, err := users.TokenVersion(ctx, other.ID)
	require.NoError(t, err)
	assert.Equal(t, int32(0), otherVersion)
}

func TestUsers_ClearPasswordRemovesOnlyThePassword(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	users := &pgUserPort{q: sqlc.New(repos.pool)}

	hash := "stored-hash"
	name := "Ada"
	created, err := users.Create(ctx, "ada@example.com", &name, &hash)
	require.NoError(t, err)
	require.Equal(t, hash, created.PasswordHash)
	other, err := users.Create(ctx, "bob@example.com", nil, &hash)
	require.NoError(t, err)

	require.NoError(t, users.ClearPassword(ctx, created.ID))

	got, err := users.GetByEmail(ctx, "ada@example.com")
	require.NoError(t, err)
	assert.Empty(t, got.PasswordHash, "the password can no longer be verified")
	assert.Equal(t, "ada@example.com", got.Email)
	require.NotNil(t, got.DisplayName)
	assert.Equal(t, "Ada", *got.DisplayName, "only the password column changes")

	untouched, err := users.GetByEmail(ctx, "bob@example.com")
	require.NoError(t, err)
	assert.Equal(t, other.ID, untouched.ID)
	assert.Equal(t, hash, untouched.PasswordHash, "other accounts keep their password")

	assert.NoError(t, users.ClearPassword(ctx, created.ID), "clearing twice is harmless, so a retry works")
}
