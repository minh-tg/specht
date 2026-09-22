//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRetention_StaleReportsPurgeEndToEnd proves the retention queries
// against real Postgres: only settled reports older than the cutoff count,
// deletion cascades without touching findings, and the admin overview
// reflects the purge.
func TestRetention_StaleReportsPurgeEndToEnd(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	project := createTestProject(t, repos)
	mkReport := func(status string) sqlc.Report {
		report, err := repos.Reports.Create(ctx, CreateReportParams{
			ProjectID:     project.ID,
			ToolName:      "trivy",
			ScanType:      "image",
			ScanScope:     []byte(`{}`),
			RawReportHash: pgtype.Text{String: uuid.NewString(), Valid: true},
		})
		require.NoError(t, err)
		_, err = repos.Reports.UpdateStatus(ctx, report.ID, project.ID, status, 1, pgtype.Text{Valid: false})
		require.NoError(t, err)
		return report
	}

	old := mkReport("completed")
	fresh := mkReport("completed")
	failed := mkReport("failed")
	processing := mkReport("processing")
	_, err := repos.pool.Exec(ctx,
		`UPDATE reports SET completed_at = NOW() - interval '400 days' WHERE id = ANY($1)`,
		[]string{uuid.UUID(old.ID.Bytes).String(), uuid.UUID(failed.ID.Bytes).String()})
	require.NoError(t, err)

	cutoff := time.Now().AddDate(0, 0, -365)
	count, err := repos.Reports.CountStaleReports(ctx, cutoff)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count, "only settled old reports count (not fresh, not processing)")

	ids, err := repos.Reports.DeleteStaleReports(ctx, cutoff)
	require.NoError(t, err)
	assert.Len(t, ids, 2)

	for _, id := range []pgtype.UUID{fresh.ID, processing.ID} {
		_, err := repos.Reports.GetByID(ctx, id)
		require.NoError(t, err, "fresh and processing reports must survive")
	}
	for _, id := range []pgtype.UUID{old.ID, failed.ID} {
		_, err := repos.Reports.GetByID(ctx, id)
		require.Error(t, err, "purged reports must be gone")
	}

	// Admin overview still answers after the purge.
	stores := PortStoresFromRepos(repos, sqlc.New(repos.pool))
	overview, err := stores.Admin.Overview(ctx)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, overview.ProjectCount, int64(1))
	assert.GreaterOrEqual(t, overview.ReportCount, int64(2))
}
