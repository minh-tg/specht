//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db"
)

// CI rolls the chain back on an empty schema. This test rolls 000060 and later
// back on a database that holds rows those migrations touch, then applies the
// chain again, and checks which values come back: the decision_reason
// backfill, the alias dimension an ingest re-saw, and the declared scan filter
// of a report, which must not read as unfiltered after the round trip.
func TestMigrationsRollBackWithData(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	dsn := repos.pool.Config().ConnString()
	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := repos.pool.Exec(ctx, sql, args...)
		require.NoError(t, err, sql)
	}
	version := func() int64 {
		var v int64
		require.NoError(t, repos.pool.QueryRow(ctx, `SELECT version FROM schema_migrations`).Scan(&v))
		return v
	}
	latest := version()

	project := createTestProject(t, repos)
	exec(`INSERT INTO waivers (project_id, name, enabled, status, reason, decision_note, decision_reason, decided_at)
		VALUES ($1, 'swept', false, 'rejected', 'r', 'expired before a decision', 'expired', NOW())`, project.ID)
	exec(`INSERT INTO findings (project_id, finding_kind, fingerprint, current_title, current_severity, current_severity_rank, state, triage_status, first_seen_at, last_seen_at)
		VALUES ($1, 'sca', 'fp-alias', 't', 'high', 3, 'open', 'untriaged', NOW(), NOW())`, project.ID)
	exec(`INSERT INTO finding_dimensions (finding_id, dim_key, dim_value, source)
		SELECT id, 'alias', 'GHSA-xxxx', 'backfill' FROM findings WHERE fingerprint = 'fp-alias'`)
	exec(`INSERT INTO finding_dimensions (finding_id, dim_key, dim_value, source)
		SELECT id, 'alias', 'CVE-2026-0001', 'trivy' FROM findings WHERE fingerprint = 'fp-alias'`)
	exec(`INSERT INTO reports (project_id, tool_name, scan_type, status, total_findings, covered_finding_kinds, examined_keys, filter_severities, filter_fixable_only)
		VALUES ($1, 'trivy', 'image', 'completed', 0, ARRAY['sca'], ARRAY['fp:x'], ARRAY['high', 'critical'], true)`, project.ID)
	exec(`INSERT INTO reports (project_id, tool_name, scan_type, status, total_findings, covered_finding_kinds, examined_keys)
		VALUES ($1, 'grype', 'image', 'completed', 0, ARRAY['sca'], ARRAY['fp:y'])`, project.ID)

	for version() > 59 {
		before := version()
		require.NoError(t, db.RollbackMigrations(dsn, "../../migrations"))
		require.Less(t, version(), before)
	}
	var aliases []string
	rows, err := repos.pool.Query(ctx, `SELECT dim_value FROM finding_dimensions WHERE dim_key = 'alias' ORDER BY dim_value`)
	require.NoError(t, err)
	for rows.Next() {
		var v string
		require.NoError(t, rows.Scan(&v))
		aliases = append(aliases, v)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"CVE-2026-0001"}, aliases, "000061 down removes only rows still marked backfill")

	require.NoError(t, db.RunMigrations(dsn, "../../migrations"))
	require.Equal(t, latest, version())

	var reason *string
	require.NoError(t, repos.pool.QueryRow(ctx, `SELECT decision_reason FROM waivers WHERE name = 'swept'`).Scan(&reason))
	require.NotNil(t, reason)
	assert.Equal(t, "expired", *reason, "000068 up backfills the reason again from the note")

	var severities []string
	var fixableOnly bool
	require.NoError(t, repos.pool.QueryRow(ctx,
		`SELECT filter_severities, filter_fixable_only FROM reports WHERE tool_name = 'trivy'`).Scan(&severities, &fixableOnly))
	assert.Equal(t, []string{"high", "critical"}, severities, "the declared scan filter survives a rollback and re-apply")
	assert.True(t, fixableOnly)

	var unfiltered []string
	var unfilteredFixable bool
	require.NoError(t, repos.pool.QueryRow(ctx,
		`SELECT COALESCE(filter_severities, '{}'), filter_fixable_only FROM reports WHERE tool_name = 'grype'`).Scan(&unfiltered, &unfilteredFixable))
	assert.Empty(t, unfiltered)
	assert.False(t, unfilteredFixable)

	var backup bool
	require.NoError(t, repos.pool.QueryRow(ctx, `SELECT to_regclass('migration_000067_report_filters') IS NOT NULL`).Scan(&backup))
	assert.False(t, backup, "the backup is dropped once the filters are restored")
}
