//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type carryReportSpec struct {
	branch, base, scope, status string
	ageSecs                     float64
}

func mkCarryReport(t *testing.T, repos *Repos, projectID pgtype.UUID, s carryReportSpec) pgtype.UUID {
	t.Helper()
	ctx := context.Background()
	report, err := repos.Reports.Create(ctx, CreateReportParams{
		ProjectID:     projectID,
		ToolName:      "trivy",
		ScanType:      "image",
		ScanScope:     []byte(`{}`),
		ScanScopeHash: pgtype.Text{String: s.scope, Valid: true},
		Branch:        pgtype.Text{String: s.branch, Valid: s.branch != ""},
		BaseRevision:  pgtype.Text{String: s.base, Valid: s.base != ""},
		CommitSha:     pgtype.Text{String: uuid.NewString()[:8], Valid: true},
		ScanMode:      "full",
		RawReportHash: pgtype.Text{String: uuid.NewString(), Valid: true},
	})
	require.NoError(t, err)
	if s.status != "processing" {
		_, err = repos.Reports.UpdateStatus(ctx, report.ID, projectID, s.status, 1, pgtype.Text{})
		require.NoError(t, err)
	}
	_, err = repos.pool.Exec(ctx,
		`UPDATE reports SET created_at = NOW() - make_interval(secs => $2) WHERE id = $1`,
		report.ID, s.ageSecs)
	require.NoError(t, err)
	return report.ID
}

// TestPreviousCompletedInScope_NewestEarlierCompletedSameScope proves the
// carry source query: only completed reports in the same scan scope created
// before the current report qualify, and the newest of them wins.
func TestPreviousCompletedInScope_NewestEarlierCompletedSameScope(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	other := createTestProject(t, repos)

	mk := func(s carryReportSpec) pgtype.UUID { return mkCarryReport(t, repos, project.ID, s) }
	mk(carryReportSpec{branch: "feat/x", scope: "scope-a", status: "completed", ageSecs: 3600})
	want := mk(carryReportSpec{branch: "feat/x", scope: "scope-a", status: "completed", ageSecs: 600})
	mk(carryReportSpec{branch: "feat/x", scope: "scope-a", status: "failed", ageSecs: 300})
	mk(carryReportSpec{branch: "feat/x", scope: "scope-b", status: "completed", ageSecs: 200})
	mkCarryReport(t, repos, other.ID, carryReportSpec{branch: "feat/x", scope: "scope-a", status: "completed", ageSecs: 100})
	current := mk(carryReportSpec{branch: "feat/x", scope: "scope-a", status: "processing", ageSecs: 60})
	// A completed report in the scope created after the current one is not
	// earlier and must not be picked.
	mk(carryReportSpec{branch: "feat/x", scope: "scope-a", status: "completed", ageSecs: 10})

	got, err := repos.Reports.PreviousCompletedInScope(ctx, project.ID, current)
	require.NoError(t, err)
	assert.Equal(t, want, got)

	first := mk(carryReportSpec{branch: "feat/y", scope: "scope-c", status: "processing", ageSecs: 5})
	_, err = repos.Reports.PreviousCompletedInScope(ctx, project.ID, first)
	assert.ErrorIs(t, err, pgx.ErrNoRows, "the first report of a scope has nothing to carry from")

	_, err = repos.Reports.PreviousCompletedInScope(ctx, other.ID, current)
	assert.ErrorIs(t, err, pgx.ErrNoRows, "a report of another project never resolves")
}

// TestBranchHasChangeReport_BaseOtherThanBranch proves the change-branch
// test: a report on the branch must name a non-empty base revision other
// than the branch itself.
func TestBranchHasChangeReport_BaseOtherThanBranch(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	other := createTestProject(t, repos)

	mk := func(s carryReportSpec) { mkCarryReport(t, repos, project.ID, s) }
	mk(carryReportSpec{branch: "main", scope: "s", status: "completed"})
	mk(carryReportSpec{branch: "main", base: "main", scope: "s", status: "completed"})
	mk(carryReportSpec{branch: "feat/x", base: "main", scope: "s", status: "failed"})
	mk(carryReportSpec{branch: "push-only", scope: "s", status: "completed"})
	mkCarryReport(t, repos, other.ID, carryReportSpec{branch: "foreign", base: "main", scope: "s", status: "completed"})

	for branch, want := range map[string]bool{
		"main":      false,
		"feat/x":    true,
		"push-only": false,
		"foreign":   false,
		"unknown":   false,
	} {
		got, err := repos.Reports.BranchHasChangeReport(ctx, project.ID, branch)
		require.NoError(t, err)
		assert.Equal(t, want, got, "branch %q", branch)
	}
}

// TestListReportIntroducedChangeTypes_OnlyRequestedIntroducedRows proves the
// carry lookup returns the recorded change type for the requested findings
// one report introduced, and nothing for findings it did not introduce.
func TestListReportIntroducedChangeTypes_OnlyRequestedIntroducedRows(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	report := mkCarryReport(t, repos, project.ID, carryReportSpec{branch: "feat/x", scope: "s", status: "completed"})
	otherReport := mkCarryReport(t, repos, project.ID, carryReportSpec{branch: "feat/x", scope: "s", status: "completed"})

	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	mkFinding := func(fp string) pgtype.UUID {
		f, err := repos.Findings.Upsert(ctx, UpsertFindingParams{
			ProjectID: project.ID, FindingKind: "sca", Fingerprint: fp,
			CurrentTitle: fp, Severity: "high", SeverityRank: 3,
			FirstSeenAt: now, LastSeenAt: now,
		})
		require.NoError(t, err)
		return f.ID
	}
	fNew, fReg, fOther, fUnrequested := mkFinding("fp-new"), mkFinding("fp-reg"), mkFinding("fp-other"), mkFinding("fp-unrequested")
	require.NoError(t, repos.Findings.RecordReportIntroducedFindings(ctx, report, pgtype.UUID{},
		[]pgtype.UUID{fNew, fReg, fUnrequested}, []string{"new", "regression", "new"}))
	require.NoError(t, repos.Findings.RecordReportIntroducedFindings(ctx, otherReport, pgtype.UUID{},
		[]pgtype.UUID{fOther}, []string{"new"}))

	port := newFindingPort(repos.Findings.(*pgFindingRepo))
	got, err := port.ListReportIntroducedChangeTypes(ctx, toUUID(report), []string{toUUID(fNew), toUUID(fReg), toUUID(fOther)})
	require.NoError(t, err)
	assert.Equal(t, map[string]string{toUUID(fNew): "new", toUUID(fReg): "regression"}, got)

	empty, err := port.ListReportIntroducedChangeTypes(ctx, toUUID(report), nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}
