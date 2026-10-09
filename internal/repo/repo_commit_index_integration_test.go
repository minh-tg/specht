//go:build integration

package repo

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReportsCommitLookupUsesTheProjectCommitIndex(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	conn, err := repos.pool.Acquire(ctx)
	require.NoError(t, err)
	defer conn.Release()

	// An empty table makes a sequential scan the cheapest plan, so turn it off
	// to see whether the index can serve the lookup at all.
	_, err = conn.Exec(ctx, `SET enable_seqscan = off`)
	require.NoError(t, err)

	rows, err := conn.Query(ctx, `
		EXPLAIN SELECT EXISTS (
			SELECT 1 FROM reports
			WHERE project_id = '00000000-0000-0000-0000-000000000001'
			  AND commit_sha = 'abc123' AND status = 'completed')`)
	require.NoError(t, err)
	var plan []string
	for rows.Next() {
		var line string
		require.NoError(t, rows.Scan(&line))
		plan = append(plan, line)
	}
	require.NoError(t, rows.Err())
	assert.Contains(t, strings.Join(plan, "\n"), "idx_reports_project_commit")
}
