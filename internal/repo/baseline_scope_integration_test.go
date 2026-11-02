//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBaselineLookupAndEvidenceStayInOneScanScope proves that a trunk scanning
// two images keeps them apart: the scoped branch lookup returns the newest
// report of the requested image, and the evidence history of an image-a
// baseline never asks the newer image-b scan, which cannot see image-a.
func TestBaselineLookupAndEvidenceStayInOneScanScope(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}

	f, err := repos.Findings.Upsert(ctx, UpsertFindingParams{
		ProjectID: project.ID, FindingKind: "sca", Fingerprint: "cve-in-image-a",
		CurrentTitle: "x", Severity: "high", SeverityRank: 3, FirstSeenAt: now, LastSeenAt: now,
	})
	require.NoError(t, err)
	observe := func(report pgtype.UUID) {
		t.Helper()
		_, err := repos.Findings.CreateOccurrence(ctx, CreateOccurrenceParams{
			FindingID: f.ID, ReportID: report, Title: "t", Severity: "high", SeverityRank: 3,
			ToolName: "trivy", Display: []byte(`{}`), Metadata: []byte(`{}`),
		})
		require.NoError(t, err)
	}
	observe(mkCarryReport(t, repos, project.ID, carryReportSpec{branch: "main", scope: "image-a", status: "completed", ageSecs: 300}))
	olderB := mkCarryReport(t, repos, project.ID, carryReportSpec{branch: "main", scope: "image-b", status: "completed", ageSecs: 200})
	newerA := mkCarryReport(t, repos, project.ID, carryReportSpec{branch: "main", scope: "image-a", status: "completed", ageSecs: 100})
	imageB := mkCarryReport(t, repos, project.ID, carryReportSpec{branch: "main", scope: "image-b", status: "completed", ageSecs: 10})
	// A fixable-only image-a scan that omits the finding cannot speak for it,
	// so the older image-a scan answers, not the newer image-b scan.
	_, err = repos.pool.Exec(ctx, `UPDATE reports SET filter_fixable_only = true WHERE id = $1`, newerA)
	require.NoError(t, err)

	main := pgtype.Text{String: "main", Valid: true}
	anyScope, err := repos.Reports.GetLatestFullByBranch(ctx, project.ID, "trivy", main)
	require.NoError(t, err)
	assert.Equal(t, imageB, anyScope.ID, "the branch-wide lookup still returns the newest report of any scope")
	scoped, err := repos.Reports.GetLatestFullByBranchInScope(ctx, project.ID, "trivy", main, "image-a")
	require.NoError(t, err)
	assert.Equal(t, newerA, scoped.ID)
	_, err = repos.Reports.GetLatestFullByBranchInScope(ctx, project.ID, "trivy", main, "image-c")
	assert.ErrorIs(t, err, pgx.ErrNoRows)

	port := newFindingPort(repos.Findings.(*pgFindingRepo))
	got, err := port.ListBaselineEvidence(ctx, toUUID(newerA), []string{toUUID(f.ID)})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{toUUID(f.ID): true}, got,
		"main still has the finding in image-a; the image-b scan cannot vouch for its absence")

	// An image-b baseline speaks for its own scope only.
	got, err = port.ListBaselineEvidence(ctx, toUUID(olderB), []string{toUUID(f.ID)})
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{toUUID(f.ID): false}, got)
}
