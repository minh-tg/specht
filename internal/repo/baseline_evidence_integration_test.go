//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListBaselineEvidence_FilteredBaselineDefersToEarlierTrunkScans proves
// the baseline evidence query: the newest report of the baseline's branch that
// observed a finding or could have answers for it. A fixable-only baseline
// cannot speak for a finding without a fix that it omits, so the unfiltered
// main scan before it does; reports of other branches and of later times never
// answer, and a finding no report speaks for has no entry.
func TestListBaselineEvidence_FilteredBaselineDefersToEarlierTrunkScans(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)

	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	mkFinding := func(fp string, fixedIn string) pgtype.UUID {
		t.Helper()
		f, err := repos.Findings.Upsert(ctx, UpsertFindingParams{
			ProjectID: project.ID, FindingKind: "sca", Fingerprint: fp,
			CurrentTitle: fp, Severity: "high", SeverityRank: 3,
			FirstSeenAt: now, LastSeenAt: now,
		})
		require.NoError(t, err)
		if fixedIn != "" {
			_, err = repos.pool.Exec(ctx,
				`INSERT INTO finding_dimensions (finding_id, dim_key, dim_value) VALUES ($1, 'fixed_version', $2)`, f.ID, fixedIn)
			require.NoError(t, err)
		}
		return f.ID
	}
	observe := func(finding, report pgtype.UUID) {
		t.Helper()
		_, err := repos.Findings.CreateOccurrence(ctx, CreateOccurrenceParams{
			FindingID: finding, ReportID: report, Title: "t", Severity: "high", SeverityRank: 3,
			ToolName: "trivy", Display: []byte(`{}`), Metadata: []byte(`{}`),
		})
		require.NoError(t, err)
	}
	filter := func(report pgtype.UUID, severities []string, fixableOnly bool) {
		t.Helper()
		var sev any
		if severities != nil {
			sev = severities
		}
		_, err := repos.pool.Exec(ctx,
			`UPDATE reports SET filter_severities = $2::text[], filter_fixable_only = $3 WHERE id = $1`,
			report, sev, fixableOnly)
		require.NoError(t, err)
	}
	mk := func(branch string, age float64) pgtype.UUID {
		return mkCarryReport(t, repos, project.ID, carryReportSpec{branch: branch, scope: branch, status: "completed", ageSecs: age})
	}

	debt := mkFinding("debt", "")          // main's open debt without a fix
	fixable := mkFinding("fixable", "1.2") // has a fix
	gone := mkFinding("gone", "")          // main fixed it before the baseline
	strange := mkFinding("strange", "")    // only another branch has it

	full := mk("main", 3000)
	observe(debt, full)
	observe(fixable, full)
	mid := mk("main", 2000)
	observe(debt, mid)
	observe(fixable, mid)
	other := mk("feat/other", 1500)
	observe(strange, other)
	baseline := mk("main", 1000)
	filter(baseline, nil, true)
	observe(fixable, baseline)
	later := mk("main", 10)
	observe(gone, later)

	port := newFindingPort(repos.Findings.(*pgFindingRepo))
	ids := []string{toUUID(debt), toUUID(fixable), toUUID(gone), toUUID(strange)}
	got, err := port.ListBaselineEvidence(ctx, toUUID(baseline), ids)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{
		toUUID(debt):    true,  // the unfiltered main scan before the baseline saw it
		toUUID(fixable): true,  // the baseline saw it
		toUUID(gone):    false, // the newest unfiltered main scan before the baseline did not
		toUUID(strange): false, // and main never had it
	}, got)

	// With every earlier main scan filtered by severity, nothing speaks for a
	// finding the baseline omitted.
	filter(full, []string{"high", "critical"}, false)
	filter(mid, []string{"high", "critical"}, false)
	got, err = port.ListBaselineEvidence(ctx, toUUID(baseline), ids)
	require.NoError(t, err)
	assert.Equal(t, map[string]bool{
		toUUID(debt):    true, // observed by a filtered report still counts
		toUUID(fixable): true,
	}, got)

	empty, err := port.ListBaselineEvidence(ctx, toUUID(baseline), nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}

// TestListBaselineEvidence_BranchlessBaselineSpeaksOnlyForItself proves a
// baseline without a branch never borrows evidence from other branchless
// reports.
func TestListBaselineEvidence_BranchlessBaselineSpeaksOnlyForItself(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	f, err := repos.Findings.Upsert(ctx, UpsertFindingParams{
		ProjectID: project.ID, FindingKind: "sca", Fingerprint: "x",
		CurrentTitle: "x", Severity: "high", SeverityRank: 3, FirstSeenAt: now, LastSeenAt: now,
	})
	require.NoError(t, err)
	earlier := mkCarryReport(t, repos, project.ID, carryReportSpec{scope: "s", status: "completed", ageSecs: 100})
	_, err = repos.Findings.CreateOccurrence(ctx, CreateOccurrenceParams{
		FindingID: f.ID, ReportID: earlier, Title: "t", Severity: "high", SeverityRank: 3,
		ToolName: "trivy", Display: []byte(`{}`), Metadata: []byte(`{}`),
	})
	require.NoError(t, err)
	baseline := mkCarryReport(t, repos, project.ID, carryReportSpec{scope: "s", status: "completed", ageSecs: 10})
	_, err = repos.pool.Exec(ctx, `UPDATE reports SET filter_fixable_only = true WHERE id = $1`, baseline)
	require.NoError(t, err)

	port := newFindingPort(repos.Findings.(*pgFindingRepo))
	got, err := port.ListBaselineEvidence(ctx, toUUID(baseline), []string{toUUID(f.ID)})
	require.NoError(t, err)
	assert.Empty(t, got)
}
