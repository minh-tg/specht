//go:build integration

package repo

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestFindingScopeSeverity_OneRowPerScope(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "scope-sev", Name: "Scope severity", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	now := time.Now().UTC()
	f, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
		ProjectID: project.ID, FindingKind: "sast", Fingerprint: "fp-scope", Title: "SQL injection",
		Severity: "high", SeverityRank: 3, FirstSeen: now, LastSeen: now,
	})
	require.NoError(t, err)

	write := func(scope, severity string, rank int16) {
		t.Helper()
		require.NoError(t, stores.Findings.UpsertScopeSeverity(ctx, port.FindingScopeSeverityInput{
			FindingID: f.ID, ScopeHash: scope, Severity: severity, SeverityRank: rank, ObservedAt: now,
		}))
	}
	write("main", "high", 3)
	write("feature", "low", 1)
	write("feature", "medium", 2)

	rows, err := stores.Findings.ListScopeSeverities(ctx, []string{f.ID})
	require.NoError(t, err)
	bySope := map[string]port.FindingScopeSeverity{}
	for _, r := range rows {
		bySope[r.ScopeHash] = r
	}
	require.Len(t, rows, 2, "a repeat from one scope replaces its row, so two scopes give two rows")
	assert.Equal(t, "high", bySope["main"].Severity)
	assert.Equal(t, int16(3), bySope["main"].SeverityRank)
	assert.Equal(t, "medium", bySope["feature"].Severity)
	assert.Equal(t, int16(2), bySope["feature"].SeverityRank)

	empty, err := stores.Findings.ListScopeSeverities(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

func TestFindingScopeSeverity_SeverityChangedEventIsAccepted(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "scope-event", Name: "Scope event", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	now := time.Now().UTC()
	f, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
		ProjectID: project.ID, FindingKind: "sast", Fingerprint: "fp-event", Title: "XSS",
		Severity: "high", SeverityRank: 3, FirstSeen: now, LastSeen: now,
	})
	require.NoError(t, err)

	oldValue, newValue := "high", "low"
	event, err := stores.Findings.CreateEvent(ctx, port.FindingEventInput{
		FindingID: f.ID, EventType: "severity_changed", OldValue: &oldValue, NewValue: &newValue,
		Changes: []byte(`{"scope_hash":"feature"}`),
	})
	require.NoError(t, err, "finding_events must allow severity_changed after migration 000058")
	assert.Equal(t, "severity_changed", event.EventType)
	require.NotNil(t, event.OldValue)
	require.NotNil(t, event.NewValue)
	assert.Equal(t, "high", *event.OldValue)
	assert.Equal(t, "low", *event.NewValue)
}

// TestMigration000058_BackfillsScopeSeverities rolls 000058 back, seeds
// occurrences in several scopes, and re-applies the migration. The backfill
// must keep the newest occurrence per (finding, scope).
func TestMigration000058_BackfillsScopeSeverities(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	repos := NewRepos(pool)
	c := pool.Config().ConnConfig
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", c.User, c.Password, c.Host, c.Port, c.Database)

	// Roll back to the version before 000058, then re-apply 000058 alone so its
	// backfill runs. Stepping back once would unwind only the newest migration
	// (000059 on this branch), leaving 000058 in place and skipping the backfill.
	m, err := migrate.New("file://../../migrations", dsn)
	require.NoError(t, err)
	defer func() { _, _ = m.Close() }()
	require.NoError(t, m.Migrate(57))

	project := createTestProject(t, repos)
	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	finding, err := repos.Findings.Upsert(ctx, UpsertFindingParams{
		ProjectID: project.ID, FindingKind: "sast", Fingerprint: "fp-backfill", CurrentTitle: "Path traversal",
		Severity: "low", SeverityRank: 1, FirstSeenAt: now, LastSeenAt: now,
	})
	require.NoError(t, err)

	// Each call creates a report in one scope and an occurrence for the
	// finding. The sleep keeps observed_at strictly increasing.
	observe := func(scopeHash pgtype.Text, severity string, rank int16) {
		t.Helper()
		report, err := repos.Reports.Create(ctx, CreateReportParams{
			ProjectID: project.ID, ToolName: "trivy", ScanType: "image",
			ScanScope: []byte(`{}`), ScanScopeHash: scopeHash,
			Branch: pgtype.Text{Valid: false}, CommitSha: pgtype.Text{Valid: false},
			RawReportHash: pgtype.Text{Valid: false}, ParserVersion: pgtype.Text{Valid: false},
			ToolVersion: pgtype.Text{Valid: false}, ScanTarget: pgtype.Text{Valid: false},
		})
		require.NoError(t, err)
		_, err = repos.Findings.CreateOccurrence(ctx, CreateOccurrenceParams{
			FindingID: finding.ID, ReportID: report.ID, Title: "Path traversal",
			Description: pgtype.Text{Valid: false}, Severity: severity, SeverityRank: rank,
			Score: pgtype.Numeric{Valid: false}, ToolName: "trivy",
			ToolVersion: pgtype.Text{Valid: false}, ParserVersion: pgtype.Text{Valid: false},
			LocationSummary: pgtype.Text{Valid: false}, Display: []byte(`{}`), Metadata: []byte(`{}`),
		})
		require.NoError(t, err)
		time.Sleep(10 * time.Millisecond)
	}
	observe(pgtype.Text{String: "h-main", Valid: true}, "medium", 2)
	observe(pgtype.Text{String: "h-main", Valid: true}, "high", 3)
	observe(pgtype.Text{String: "h-feature", Valid: true}, "low", 1)
	observe(pgtype.Text{Valid: false}, "critical", 4)

	require.NoError(t, m.Steps(1))

	rows, err := pool.Query(ctx, `SELECT scope_hash, severity, severity_rank FROM finding_scope_severities
		WHERE finding_id = $1 ORDER BY scope_hash`, finding.ID)
	require.NoError(t, err)
	defer rows.Close()
	type scopeRow struct {
		scope    string
		severity string
		rank     int16
	}
	var got []scopeRow
	for rows.Next() {
		var r scopeRow
		require.NoError(t, rows.Scan(&r.scope, &r.severity, &r.rank))
		got = append(got, r)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []scopeRow{
		{scope: "", severity: "critical", rank: 4},
		{scope: "h-feature", severity: "low", rank: 1},
		{scope: "h-main", severity: "high", rank: 3},
	}, got, "one row per scope, holding the newest occurrence; a missing scope hash becomes ''")
}

// TestFindingScopeSeverity_BulkUpsertKeepsLastRow writes scope rows for two
// findings in one statement. A finding that appears twice keeps its last row,
// and an existing row for the same scope is replaced.
func TestFindingScopeSeverity_BulkUpsertKeepsLastRow(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "scope-bulk", Name: "Scope bulk", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	now := time.Now().UTC()
	upsert := func(fp string) string {
		t.Helper()
		f, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
			ProjectID: project.ID, FindingKind: "sast", Fingerprint: fp, Title: fp,
			Severity: "low", SeverityRank: 1, FirstSeen: now, LastSeen: now,
		})
		require.NoError(t, err)
		return f.ID
	}
	a, b := upsert("fp-bulk-a"), upsert("fp-bulk-b")
	require.NoError(t, stores.Findings.UpsertScopeSeverity(ctx, port.FindingScopeSeverityInput{
		FindingID: a, ScopeHash: "bulk", Severity: "critical", SeverityRank: 4, ObservedAt: now,
	}))

	require.NoError(t, stores.Findings.(port.FindingIngestBatchStore).BulkUpsertScopeSeverities(ctx, []port.FindingScopeSeverityInput{
		{FindingID: a, ScopeHash: "bulk", Severity: "high", SeverityRank: 3, ObservedAt: now},
		{FindingID: b, ScopeHash: "bulk", Severity: "low", SeverityRank: 1, ObservedAt: now},
		{FindingID: a, ScopeHash: "bulk", Severity: "medium", SeverityRank: 2, ObservedAt: now},
	}))

	rows, err := stores.Findings.ListScopeSeverities(ctx, []string{a, b})
	require.NoError(t, err)
	got := map[string]port.FindingScopeSeverity{}
	for _, r := range rows {
		got[r.FindingID] = r
	}
	require.Len(t, rows, 2, "one row per (finding, scope)")
	assert.Equal(t, "medium", got[a].Severity, "the last row for a finding wins, and it replaces the earlier scope row")
	assert.Equal(t, int16(2), got[a].SeverityRank)
	assert.Equal(t, "low", got[b].Severity)
}
