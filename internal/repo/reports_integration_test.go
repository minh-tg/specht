//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

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

// TestReports_FindCompletedByReplayKey checks the replay lookup and the dedup
// index behind it against real Postgres: identical bytes dedupe per commit and
// scan scope, the same bytes at another commit or in another scope are a new
// report, a NULL commit or scope matches an empty one, and a second completed
// report with the same key still violates the index.
func TestReports_FindCompletedByReplayKey(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	project := createTestProject(t, repos)
	const hash = "shared-raw-hash"

	mkReport := func(commit, scope pgtype.Text) pgtype.UUID {
		report, err := repos.Reports.Create(ctx, CreateReportParams{
			ProjectID:     project.ID,
			ToolName:      "trivy",
			ScanType:      "image",
			ScanScope:     []byte(`{}`),
			CommitSha:     commit,
			ScanScopeHash: scope,
			RawReportHash: pgtype.Text{String: hash, Valid: true},
		})
		require.NoError(t, err)
		_, err = repos.Reports.UpdateStatus(ctx, report.ID, project.ID, "completed", 1, pgtype.Text{})
		require.NoError(t, err)
		return report.ID
	}
	lookup := func(commit, scope pgtype.Text) (pgtype.UUID, error) {
		return repos.Reports.FindCompletedByReplayKey(ctx, project.ID, pgtype.Text{String: hash, Valid: true}, commit, scope)
	}

	a := pgtype.Text{String: "aaaa1111", Valid: true}
	scopeA := pgtype.Text{String: "scope-a", Valid: true}
	scopeB := pgtype.Text{String: "scope-b", Valid: true}
	b := pgtype.Text{String: "bbbb2222", Valid: true}

	first := mkReport(a, scopeA)
	got, err := lookup(a, scopeA)
	require.NoError(t, err)
	assert.Equal(t, first, got, "same bytes, commit, and scope replay the existing report")

	_, err = lookup(a, scopeB)
	assert.ErrorIs(t, err, pgx.ErrNoRows, "the same commit in another scope is a new report")

	_, err = lookup(b, scopeA)
	assert.ErrorIs(t, err, pgx.ErrNoRows, "identical bytes at another commit are a new report")

	second := mkReport(b, scopeA)
	got, err = lookup(b, scopeA)
	require.NoError(t, err)
	assert.Equal(t, second, got)

	nulls := mkReport(pgtype.Text{Valid: false}, pgtype.Text{Valid: false})
	got, err = lookup(pgtype.Text{Valid: false}, pgtype.Text{Valid: false})
	require.NoError(t, err)
	assert.Equal(t, nulls, got, "NULL commit and scope match NULL")
	got, err = lookup(pgtype.Text{String: "", Valid: true}, pgtype.Text{String: "", Valid: true})
	require.NoError(t, err)
	assert.Equal(t, nulls, got, "NULL commit and scope compare as empty strings")

	// A second completed report with the same key is still a duplicate: the
	// index (not just the lookup) enforces the wider key.
	dup, err := repos.Reports.Create(ctx, CreateReportParams{
		ProjectID:     project.ID,
		ToolName:      "trivy",
		ScanType:      "image",
		ScanScope:     []byte(`{}`),
		CommitSha:     a,
		ScanScopeHash: scopeA,
		RawReportHash: pgtype.Text{String: hash, Valid: true},
	})
	require.NoError(t, err)
	_, err = repos.Reports.UpdateStatus(ctx, dup.ID, project.ID, "completed", 1, pgtype.Text{})
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	assert.Equal(t, "23505", pgErr.Code, "the dedup index rejects a same-key duplicate")
}

// TestReports_DeleteDuplicateReportKeepsAttribution reproduces the duplicate
// race interleaving against real Postgres: a finding first introduced by the
// losing processing report must keep its attribution when that report is
// deleted, so cleanup re-points it at the winner instead of letting the
// ON DELETE SET NULL foreign key null it. The loser's occurrence and
// report_introduced_findings rows cascade; the winner's stay.
func TestReports_DeleteDuplicateReportKeepsAttribution(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	project := createTestProject(t, repos)

	mkReport := func(commit string) pgtype.UUID {
		report, err := repos.Reports.Create(ctx, CreateReportParams{
			ProjectID:     project.ID,
			ToolName:      "trivy",
			ScanType:      "image",
			ScanScope:     []byte(`{}`),
			CommitSha:     pgtype.Text{String: commit, Valid: true},
			ScanScopeHash: pgtype.Text{String: "scope", Valid: true},
			RawReportHash: pgtype.Text{String: uuid.NewString(), Valid: true},
		})
		require.NoError(t, err)
		return report.ID
	}
	winner := mkReport("race-commit")
	_, err := repos.Reports.UpdateStatus(ctx, winner, project.ID, "completed", 1, pgtype.Text{})
	require.NoError(t, err)
	loser := mkReport("race-commit")

	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	finding, err := repos.Findings.Upsert(ctx, UpsertFindingParams{
		ProjectID:    project.ID,
		FindingKind:  "sca",
		Fingerprint:  "pkg:npm/lodash@4.17.20",
		CurrentTitle: "CVE-2026-1234",
		Severity:     "high",
		SeverityRank: 3,
		Score:        pgtype.Numeric{Valid: false},
		FirstSeenAt:  now,
		LastSeenAt:   now,
	})
	require.NoError(t, err)

	// The loser writes the finding first and attributes it to itself; the
	// winner then observes the attribution and leaves it alone.
	if _, err := repos.Findings.SetIntroducedBy(ctx, finding.ID, loser, pgtype.Text{String: "race-commit", Valid: true}); err != nil {
		require.NoError(t, err)
	}
	for _, reportID := range []pgtype.UUID{winner, loser} {
		if _, err := repos.Findings.CreateOccurrence(ctx, CreateOccurrenceParams{
			FindingID:       finding.ID,
			ReportID:        reportID,
			Title:           "CVE-2026-1234 in lodash",
			Description:     pgtype.Text{Valid: false},
			Severity:        "high",
			SeverityRank:    3,
			Score:           pgtype.Numeric{Valid: false},
			ToolName:        "trivy",
			ToolVersion:     pgtype.Text{Valid: false},
			ParserVersion:   pgtype.Text{Valid: false},
			LocationSummary: pgtype.Text{String: "package-lock.json", Valid: true},
			Display:         []byte(`{}`),
			Metadata:        []byte(`{}`),
		}); err != nil {
			require.NoError(t, err)
		}
		if err := repos.Findings.RecordReportIntroducedFindings(ctx, reportID, pgtype.UUID{}, []pgtype.UUID{finding.ID}, []string{"new"}); err != nil {
			require.NoError(t, err)
		}
	}

	require.NoError(t, repos.Reports.DeleteDuplicateReport(ctx, loser, project.ID, winner))

	got, err := repos.Findings.GetByID(ctx, finding.ID)
	require.NoError(t, err, "the shared finding row survives the loser's removal")
	require.True(t, got.IntroducedByReportID.Valid)
	assert.Equal(t, winner, got.IntroducedByReportID, "attribution moves to the winner")

	winnerOcc, err := repos.Findings.HasOccurrence(ctx, finding.ID, winner)
	require.NoError(t, err)
	assert.True(t, winnerOcc, "the winner's occurrence is intact")
	loserOcc, err := repos.Findings.HasOccurrence(ctx, finding.ID, loser)
	require.NoError(t, err)
	assert.False(t, loserOcc, "the loser's occurrence cascades away")

	_, err = repos.Reports.GetByID(ctx, loser)
	assert.ErrorIs(t, err, pgx.ErrNoRows, "the loser report is gone")

	var winnerRows, loserRows int
	require.NoError(t, repos.pool.QueryRow(ctx,
		`SELECT count(*) FROM report_introduced_findings WHERE report_id = $1`, winner).Scan(&winnerRows))
	require.NoError(t, repos.pool.QueryRow(ctx,
		`SELECT count(*) FROM report_introduced_findings WHERE report_id = $1`, loser).Scan(&loserRows))
	assert.Equal(t, 1, winnerRows, "the winner keeps its own report_introduced_findings row")
	assert.Equal(t, 0, loserRows, "the loser's report_introduced_findings rows cascade")
}
