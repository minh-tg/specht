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

	// Give the planner actual history. On an empty table, any project-level
	// index can look equally cheap even if it must filter every completed row.
	_, err = conn.Exec(ctx, `
		INSERT INTO projects (id, slug, name)
		VALUES ('00000000-0000-0000-0000-000000000001', 'commit-index', 'Commit index');
		INSERT INTO reports (project_id, tool_name, scan_type, status, commit_sha, completed_at)
		SELECT '00000000-0000-0000-0000-000000000001', 'trivy', 'image', 'completed',
		       CASE WHEN n = 500 THEN 'abc123' ELSE 'revision-' || n END, NOW()
		FROM generate_series(1, 1000) AS n;
		ANALYZE reports`)
	require.NoError(t, err)

	// Require an index plan, and keep the assertion specific to commit lookup.
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
