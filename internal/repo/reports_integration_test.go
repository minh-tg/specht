//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
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

// TestReports_FindCompletedByHashAndCommit checks the replay lookup and the
// dedup index behind it against real Postgres: identical bytes dedupe per
// commit, the same bytes at another commit are a new report, a NULL commit
// matches an empty commit, and a second completed report with the same bytes
// and commit still violates the index.
func TestReports_FindCompletedByHashAndCommit(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	project := createTestProject(t, repos)
	const hash = "shared-raw-hash"

	mkReport := func(commit pgtype.Text) pgtype.UUID {
		report, err := repos.Reports.Create(ctx, CreateReportParams{
			ProjectID:     project.ID,
			ToolName:      "trivy",
			ScanType:      "image",
			ScanScope:     []byte(`{}`),
			CommitSha:     commit,
			RawReportHash: pgtype.Text{String: hash, Valid: true},
		})
		require.NoError(t, err)
		_, err = repos.Reports.UpdateStatus(ctx, report.ID, project.ID, "completed", 1, pgtype.Text{})
		require.NoError(t, err)
		return report.ID
	}
	lookup := func(commit pgtype.Text) (pgtype.UUID, error) {
		return repos.Reports.FindCompletedByHashAndCommit(ctx, project.ID, pgtype.Text{String: hash, Valid: true}, commit)
	}

	first := mkReport(pgtype.Text{String: "aaaa1111", Valid: true})
	got, err := lookup(pgtype.Text{String: "aaaa1111", Valid: true})
	require.NoError(t, err)
	assert.Equal(t, first, got, "same bytes and commit replay the existing report")

	_, err = lookup(pgtype.Text{String: "bbbb2222", Valid: true})
	assert.ErrorIs(t, err, pgx.ErrNoRows, "identical bytes at another commit are a new report")

	second := mkReport(pgtype.Text{String: "bbbb2222", Valid: true})
	got, err = lookup(pgtype.Text{String: "bbbb2222", Valid: true})
	require.NoError(t, err)
	assert.Equal(t, second, got)

	nullCommit := mkReport(pgtype.Text{Valid: false})
	got, err = lookup(pgtype.Text{Valid: false})
	require.NoError(t, err)
	assert.Equal(t, nullCommit, got, "a NULL stored commit matches a NULL request commit")
	got, err = lookup(pgtype.Text{String: "", Valid: true})
	require.NoError(t, err)
	assert.Equal(t, nullCommit, got, "a NULL commit compares as the empty string")

	// A second completed report with the same bytes and commit is still a
	// duplicate: the index (not just the lookup) enforces the new key.
	dup, err := repos.Reports.Create(ctx, CreateReportParams{
		ProjectID:     project.ID,
		ToolName:      "trivy",
		ScanType:      "image",
		ScanScope:     []byte(`{}`),
		CommitSha:     pgtype.Text{Valid: false},
		RawReportHash: pgtype.Text{String: hash, Valid: true},
	})
	require.NoError(t, err)
	_, err = repos.Reports.UpdateStatus(ctx, dup.ID, project.ID, "completed", 1, pgtype.Text{})
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	assert.Equal(t, "23505", pgErr.Code, "the dedup index rejects a same-commit duplicate")
}
