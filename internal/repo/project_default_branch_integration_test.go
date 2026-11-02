//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db"
	"github.com/minh-tg/specht/internal/port"
)

func TestProjectDefaultBranch_UpdateWritesAndClears(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	_, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "branchy", Name: "Branchy", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)

	main := "main"
	updated, err := stores.Projects.Update(ctx, "branchy", port.ProjectUpdate{SetDefaultBranch: true, DefaultBranch: &main})
	require.NoError(t, err)
	require.NotNil(t, updated.DefaultBranch)
	assert.Equal(t, "main", *updated.DefaultBranch)

	read, err := stores.Projects.GetBySlug(ctx, "branchy")
	require.NoError(t, err)
	require.NotNil(t, read.DefaultBranch)
	assert.Equal(t, "main", *read.DefaultBranch)

	cleared, err := stores.Projects.Update(ctx, "branchy", port.ProjectUpdate{SetDefaultBranch: true})
	require.NoError(t, err)
	assert.Nil(t, cleared.DefaultBranch)

	for _, bad := range []string{"", " main", "main "} {
		_, err := pool.Exec(ctx, `UPDATE projects SET default_branch = $1 WHERE slug = 'branchy'`, bad)
		assert.Error(t, err, "%q", bad)
	}
}

// The 000072 down migration drops the column; applying it again restores it.
func TestProjectDefaultBranchMigrationRollback(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	dsn := repos.pool.Config().ConnString()
	hasColumn := func() bool {
		t.Helper()
		var n int
		require.NoError(t, repos.pool.QueryRow(ctx,
			`SELECT count(*) FROM information_schema.columns WHERE table_name = 'projects' AND column_name = 'default_branch'`).Scan(&n))
		return n == 1
	}
	require.True(t, hasColumn())
	for {
		var version int
		require.NoError(t, repos.pool.QueryRow(ctx, `SELECT version FROM schema_migrations`).Scan(&version))
		if version < 72 {
			break
		}
		require.NoError(t, db.RollbackMigrations(dsn, "../../migrations"))
	}
	assert.False(t, hasColumn())
	require.NoError(t, db.RunMigrations(dsn, "../../migrations"))
	assert.True(t, hasColumn())
}
