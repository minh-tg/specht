//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The archived-findings down has to drop report_deleted events and the
// archived state for the older checks, and it keeps a copy of both.
func TestDownMigrations_ArchivedFindingsDownKeepsACopy(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	pool := repos.pool

	m, err := migrate.New("file://../../migrations", pool.Config().ConnString())
	require.NoError(t, err)
	defer func() { _, _ = m.Close() }()
	require.NoError(t, m.Migrate(49))

	var projectID, findingID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, deployment_threshold, settings)
		VALUES ('archived-down', 'Archived', 'high', '{}') RETURNING id`).Scan(&projectID))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO findings (project_id, finding_kind, fingerprint, current_title, current_severity, current_severity_rank, state)
		VALUES ($1, 'sca', 'fp-1', 'CVE-1', 'high', 3, 'archived') RETURNING id`, projectID).Scan(&findingID))
	_, err = pool.Exec(ctx, `
		INSERT INTO finding_events (finding_id, event_type, old_value, new_value)
		VALUES ($1, 'report_deleted', 'open', 'archived')`, findingID)
	require.NoError(t, err)

	require.NoError(t, m.Migrate(48))

	var state string
	require.NoError(t, pool.QueryRow(ctx, `SELECT state FROM findings WHERE id = $1`, findingID).Scan(&state))
	assert.Equal(t, "fixed", state)

	var saved, events int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM migration_000049_archived_findings WHERE finding_id = $1`, findingID).Scan(&saved))
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM migration_000049_report_deleted_events WHERE finding_id = $1 AND new_value = 'archived'`, findingID).Scan(&events))
	assert.Equal(t, 1, saved, "the archived finding id is kept")
	assert.Equal(t, 1, events, "the report_deleted event is kept")

	require.NoError(t, m.Up())
	require.NoError(t, m.Migrate(48), "a second rollback finds the backup tables in place")
	require.NoError(t, m.Up())
}
