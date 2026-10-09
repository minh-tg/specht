//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReports_HasCompletedReportForCommit checks the PR-check evidence lookup
// against real Postgres: a completed scan of the exact commit counts from any
// scanner, while processing, failed, and other-commit reports do not.
func TestReports_HasCompletedReportForCommit(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	project := createTestProject(t, repos)
	const commit = "abcd0000abcd0000abcd0000abcd0000abcd0000"
	const other = "1111111111111111111111111111111111111111"

	mkReport := func(tool, status, sha string) {
		report, err := repos.Reports.Create(ctx, CreateReportParams{
			ProjectID:     project.ID,
			ToolName:      tool,
			ScanType:      "image",
			ScanScope:     []byte(`{}`),
			CommitSha:     pgtype.Text{String: sha, Valid: true},
			RawReportHash: pgtype.Text{String: uuid.NewString(), Valid: true},
		})
		require.NoError(t, err)
		_, err = repos.Reports.UpdateStatus(ctx, report.ID, project.ID, status, 1, pgtype.Text{Valid: false})
		require.NoError(t, err)
	}
	lookup := func(sha string) bool {
		found, err := repos.Reports.HasCompletedReportForCommit(ctx, project.ID, pgtype.Text{String: sha, Valid: true})
		require.NoError(t, err)
		return found
	}

	assert.False(t, lookup(commit), "no report yet")

	mkReport("trivy", "processing", commit)
	mkReport("semgrep", "failed", commit)
	mkReport("trivy", "completed", other)
	assert.False(t, lookup(commit), "processing and failed scans are not evidence")

	mkReport("semgrep", "completed", commit)
	assert.True(t, lookup(commit), "a completed scan of the commit is evidence from any scanner")
	assert.False(t, lookup("2222222222222222222222222222222222222222"), "other commits stay unknown")
}
