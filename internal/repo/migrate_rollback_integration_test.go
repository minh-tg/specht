//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/minh-tg/specht/internal/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRollbackMigrations_UndoesOneMigrationPerCall(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	dsn := repos.pool.Config().ConnString()

	version := func() int64 {
		var v int64
		require.NoError(t, repos.pool.QueryRow(ctx, `SELECT version FROM schema_migrations`).Scan(&v))
		return v
	}
	latest := version()

	require.NoError(t, db.RollbackMigrations(dsn, "../../migrations"))
	assert.Equal(t, latest-1, version(), "one call undoes only the newest migration")

	var projects bool
	require.NoError(t, repos.pool.QueryRow(ctx, `SELECT to_regclass('projects') IS NOT NULL`).Scan(&projects))
	assert.True(t, projects, "earlier tables survive a single rollback")

	require.NoError(t, db.RunMigrations(dsn, "../../migrations"))
	assert.Equal(t, latest, version())
}

func TestRollbackMigrations_EmptySchemaIsNoOp(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	dsn := repos.pool.Config().ConnString()

	m, err := migrate.New("file://../../migrations", dsn)
	require.NoError(t, err)
	defer func() { _, _ = m.Close() }()
	require.NoError(t, m.Down())

	assert.NoError(t, db.RollbackMigrations(dsn, "../../migrations"))
}
