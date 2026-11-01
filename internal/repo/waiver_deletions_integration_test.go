//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWaiverDeletionsAreAppendOnly(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	_, err := repos.pool.Exec(ctx, `INSERT INTO waiver_deletions (waiver_id, project_id, deleted_by, snapshot)
		VALUES (gen_random_uuid(), $1, 'someone', '{"name":"gone"}')`, project.ID)
	require.NoError(t, err)
	count := func() int {
		var n int
		require.NoError(t, repos.pool.QueryRow(ctx, `SELECT count(*) FROM waiver_deletions`).Scan(&n))
		return n
	}

	_, err = repos.pool.Exec(ctx, `UPDATE waiver_deletions SET deleted_by = 'x'`)
	require.Error(t, err, "UPDATE is refused")
	_, err = repos.pool.Exec(ctx, `DELETE FROM waiver_deletions`)
	require.Error(t, err, "DELETE is refused while the project exists")
	_, err = repos.pool.Exec(ctx, `TRUNCATE waiver_deletions`)
	require.Error(t, err, "TRUNCATE is refused")
	_, err = repos.pool.Exec(ctx, `TRUNCATE projects CASCADE`)
	require.Error(t, err, "a TRUNCATE cascading from projects is refused")
	assert.Equal(t, 1, count(), "the record survived every attempt")

	// Deleting the project still removes its records.
	_, err = repos.pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, project.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, count(), "the project's records go with the project")
}
