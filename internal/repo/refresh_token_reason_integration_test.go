//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db"
	"github.com/minh-tg/specht/internal/port"
)

// Every way a refresh token is revoked records why, in the statement that revokes it. A refresh
// that presents the token later reads the reason to tell a replay from a revocation the person
// caused, so a path that records the wrong reason, or none, makes a password change read as a
// stolen token again.
func TestEveryRevokeRecordsItsReason(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "reason-admin@test.com", "admin")

	signIn := func(user port.User) port.RefreshToken {
		t.Helper()
		row, err := stores.RefreshTokens.Create(ctx, rotationInput(user, uuid.NewString()))
		require.NoError(t, err)
		return row
	}
	reasonOf := func(token port.RefreshToken) port.RevokeReason {
		t.Helper()
		row, err := stores.RefreshTokens.GetByHash(ctx, token.TokenHash)
		require.NoError(t, err)
		require.NotNil(t, row.RevokedAt, "the token is revoked")
		return row.RevokedReason
	}
	member := func(label string) port.User {
		return newUser(t, repos, label+"-"+uuid.NewString()+"@test.com", "member")
	}

	t.Run("a rotation", func(t *testing.T) {
		user := member("rotate")
		old := signIn(user)
		version, err := stores.Users.TokenVersion(ctx, user.ID)
		require.NoError(t, err)
		require.NoError(t, stores.RefreshTokens.Rotate(ctx, old.ID, rotationInput(user, old.FamilyID), version))
		assert.Equal(t, port.RevokeRotated, reasonOf(old))
	})

	t.Run("the reason a caller passes", func(t *testing.T) {
		user := member("explicit")
		one, chain, all := signIn(user), signIn(user), signIn(user)
		_, err := stores.RefreshTokens.Revoke(ctx, one.ID, port.RevokeLogout)
		require.NoError(t, err)
		require.NoError(t, stores.RefreshTokens.RevokeFamily(ctx, chain.FamilyID, port.RevokeReuse))
		require.NoError(t, stores.RefreshTokens.RevokeAllForUser(ctx, user.ID, port.RevokeDeactivated))
		assert.Equal(t, port.RevokeLogout, reasonOf(one))
		assert.Equal(t, port.RevokeReuse, reasonOf(chain))
		assert.Equal(t, port.RevokeDeactivated, reasonOf(all))
	})

	t.Run("a password change", func(t *testing.T) {
		user := member("change")
		token := signIn(user)
		_, err := stores.Users.ChangePasswordAndRevoke(ctx, user.ID, "$2a$10$changed", "")
		require.NoError(t, err)
		assert.Equal(t, port.RevokePasswordChanged, reasonOf(token))
	})

	t.Run("a password set without the old one", func(t *testing.T) {
		user := member("set")
		token := signIn(user)
		require.NoError(t, stores.Users.SetPassword(ctx, user.ID, "$2a$10$set"))
		assert.Equal(t, port.RevokePasswordChanged, reasonOf(token))
	})

	t.Run("a reset link", func(t *testing.T) {
		f := newResetFixture(t, repos, "reason-reset-"+uuid.NewString()+"@test.com")
		token := signIn(f.user)
		require.NoError(t, f.redeem(t))
		assert.Equal(t, port.RevokePasswordChanged, reasonOf(token))
	})

	t.Run("an SSO link", func(t *testing.T) {
		user := member("link")
		token := signIn(user)
		_, _, err := stores.Identities.LinkRevokingKeys(ctx, user.ID, "https://idp.example.com", "sub-"+uuid.NewString(), true)
		require.NoError(t, err)
		assert.Equal(t, port.RevokeSSOLinked, reasonOf(token))
	})

	t.Run("a deactivation", func(t *testing.T) {
		user := member("deactivate")
		token := signIn(user)
		_, _, err := stores.Users.Deactivate(ctx, user.ID, false)
		require.NoError(t, err)
		assert.Equal(t, port.RevokeDeactivated, reasonOf(token))
	})

	t.Run("a later revoke keeps the first reason", func(t *testing.T) {
		user := member("first")
		old := signIn(user)
		version, err := stores.Users.TokenVersion(ctx, user.ID)
		require.NoError(t, err)
		next := rotationInput(user, old.FamilyID)
		require.NoError(t, stores.RefreshTokens.Rotate(ctx, old.ID, next, version))
		_, err = stores.Users.ChangePasswordAndRevoke(ctx, user.ID, "$2a$10$later", "")
		require.NoError(t, err)

		assert.Equal(t, port.RevokeRotated, reasonOf(old), "a spent token stays a spent token, so its replay is still caught")
		assert.Equal(t, port.RevokePasswordChanged, reasonOf(port.RefreshToken{TokenHash: next.TokenHash}))
	})

	t.Run("a row revoked without a reason reads as none", func(t *testing.T) {
		user := member("none")
		token := signIn(user)
		_, err := repos.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1`, token.ID)
		require.NoError(t, err)
		assert.Equal(t, port.RevokeReason(""), reasonOf(token))
	})

	t.Run("an unknown reason is refused", func(t *testing.T) {
		user := member("unknown")
		token := signIn(user)
		_, err := stores.RefreshTokens.Revoke(ctx, token.ID, port.RevokeReason("stolen"))
		require.Error(t, err)
	})
}

// Rolling 000080 back drops revoked_reason. The down keeps the recorded reasons and applying the up
// again restores them, so a token a password change revoked does not come back reading as a replay.
// A token revoked while the migration was rolled back has no reason and stays a replay.
func TestMigration000080_RollbackKeepsTheRevokeReasons(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	dsn := repos.pool.Config().ConnString()
	version := func() int64 {
		t.Helper()
		var v int64
		require.NoError(t, repos.pool.QueryRow(ctx, `SELECT version FROM schema_migrations`).Scan(&v))
		return v
	}
	latest := version()

	user := newUser(t, repos, "reason-rollback@test.com", "member")
	changed, err := stores.RefreshTokens.Create(ctx, rotationInput(user, uuid.NewString()))
	require.NoError(t, err)
	live, err := stores.RefreshTokens.Create(ctx, rotationInput(user, uuid.NewString()))
	require.NoError(t, err)
	_, err = stores.RefreshTokens.Revoke(ctx, changed.ID, port.RevokePasswordChanged)
	require.NoError(t, err)

	for version() >= 80 {
		before := version()
		require.NoError(t, db.RollbackMigrations(dsn, "../../migrations"))
		require.Less(t, version(), before)
	}
	var backup bool
	require.NoError(t, repos.pool.QueryRow(ctx, `SELECT to_regclass('migration_000080_refresh_token_reasons') IS NOT NULL`).Scan(&backup))
	require.True(t, backup, "the down keeps the reasons it drops")
	// The rolled-back release revokes without a reason.
	_, err = repos.pool.Exec(ctx, `UPDATE refresh_tokens SET revoked_at = now() WHERE id = $1`, live.ID)
	require.NoError(t, err)

	require.NoError(t, db.RunMigrations(dsn, "../../migrations"))
	require.Equal(t, latest, version())

	reasonOf := func(id string) *string {
		t.Helper()
		var reason *string
		require.NoError(t, repos.pool.QueryRow(ctx, `SELECT revoked_reason FROM refresh_tokens WHERE id = $1`, id).Scan(&reason))
		return reason
	}
	restored := reasonOf(changed.ID)
	require.NotNil(t, restored)
	assert.Equal(t, "password_changed", *restored, "the up restores the reason the down kept")
	assert.Nil(t, reasonOf(live.ID), "a token revoked while rolled back has no reason and reads as a replay")
	require.NoError(t, repos.pool.QueryRow(ctx, `SELECT to_regclass('migration_000080_refresh_token_reasons') IS NOT NULL`).Scan(&backup))
	assert.False(t, backup, "the backup is dropped once the reasons are restored")
}
