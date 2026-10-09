//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetLatestFullByBranch_NewestCompletedFullOnBranch proves the branch
// baseline query against real Postgres: only completed full reports from the
// requested scanner and branch qualify, and the newest one wins.
func TestGetLatestFullByBranch_NewestCompletedFullOnBranch(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	project := createTestProject(t, repos)
	mkReport := func(tool, branch, commit, mode, status string, ageSecs float64) pgtype.UUID {
		report, err := repos.Reports.Create(ctx, CreateReportParams{
			ProjectID:     project.ID,
			ToolName:      tool,
			ScanType:      "image",
			ScanScope:     []byte(`{}`),
			Branch:        pgtype.Text{String: branch, Valid: true},
			CommitSha:     pgtype.Text{String: commit, Valid: true},
			ScanMode:      mode,
			RawReportHash: pgtype.Text{String: uuid.NewString(), Valid: true},
		})
		require.NoError(t, err)
		_, err = repos.Reports.UpdateStatus(ctx, report.ID, project.ID, status, 1, pgtype.Text{})
		require.NoError(t, err)
		_, err = repos.pool.Exec(ctx,
			`UPDATE reports SET created_at = NOW() - make_interval(secs => $2) WHERE id = $1`,
			report.ID, ageSecs)
		require.NoError(t, err)
		return report.ID
	}

	mkReport("trivy", "main", "aaa111", "full", "completed", 3600)
	newest := mkReport("trivy", "main", "bbb222", "full", "completed", 600)
	mkReport("trivy", "main", "ccc333", "incremental", "completed", 60)
	mkReport("trivy", "main", "ddd444", "full", "processing", 30)
	mkReport("trivy", "feature", "eee555", "full", "completed", 10)
	mkReport("grype", "main", "fff666", "full", "completed", 5)

	got, err := repos.Reports.GetLatestFullByBranch(ctx, project.ID, "trivy", pgtype.Text{String: "main", Valid: true})
	require.NoError(t, err)
	assert.Equal(t, newest, got.ID)
	assert.Equal(t, "bbb222", got.CommitSha.String)

	_, err = repos.Reports.GetLatestFullByBranch(ctx, project.ID, "trivy", pgtype.Text{String: "release", Valid: true})
	assert.ErrorIs(t, err, pgx.ErrNoRows, "a branch without a completed full report has no baseline")
}
