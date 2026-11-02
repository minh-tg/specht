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

// TestListFindingIDsOnTrunk_FollowsTheTrunkRule proves which findings count as
// still on the trunk: one with a severity row in the scan scope of a trunk
// report. With a default branch set only that branch is the trunk. Without one
// a branch without change reports and a report without a branch are.
func TestListFindingIDsOnTrunk_FollowsTheTrunkRule(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	other := createTestProject(t, repos)
	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}

	mkFinding := func(projectID pgtype.UUID, fp string) pgtype.UUID {
		t.Helper()
		f, err := repos.Findings.Upsert(ctx, UpsertFindingParams{
			ProjectID: projectID, FindingKind: "sca", Fingerprint: fp,
			CurrentTitle: fp, Severity: "high", SeverityRank: 3, FirstSeenAt: now, LastSeenAt: now,
		})
		require.NoError(t, err)
		return f.ID
	}
	inScope := func(finding pgtype.UUID, scope string) {
		t.Helper()
		_, err := repos.pool.Exec(ctx,
			`INSERT INTO finding_scope_severities (finding_id, scope_hash, severity, severity_rank) VALUES ($1, $2, 'high', 3)`,
			finding, scope)
		require.NoError(t, err)
	}

	mkCarryReport(t, repos, project.ID, carryReportSpec{branch: "main", scope: "main-scope", status: "completed"})
	mkCarryReport(t, repos, project.ID, carryReportSpec{branch: "feat/x", base: "main", scope: "feat-scope", status: "completed"})
	mkCarryReport(t, repos, project.ID, carryReportSpec{scope: "branchless-scope", status: "completed"})
	mkCarryReport(t, repos, project.ID, carryReportSpec{branch: "fresh", scope: "processing-scope", status: "processing"})

	onMain := mkFinding(project.ID, "on-main")
	inScope(onMain, "main-scope")
	onFeat := mkFinding(project.ID, "on-feat")
	inScope(onFeat, "feat-scope")
	branchless := mkFinding(project.ID, "branchless")
	inScope(branchless, "branchless-scope")
	retired := mkFinding(project.ID, "retired") // no scope row left
	pending := mkFinding(project.ID, "pending")
	inScope(pending, "processing-scope")
	foreign := mkFinding(other.ID, "foreign")
	inScope(foreign, "main-scope")

	port := newFindingPort(repos.Findings.(*pgFindingRepo))
	ids := []string{toUUID(onMain), toUUID(onFeat), toUUID(branchless), toUUID(retired), toUUID(pending), toUUID(foreign)}
	ask := func(defaultBranch *string) map[string]bool {
		t.Helper()
		got, err := port.ListFindingIDsOnTrunk(ctx, toUUID(project.ID), defaultBranch, ids)
		require.NoError(t, err)
		return got
	}
	main := "main"

	assert.Equal(t, map[string]bool{toUUID(onMain): true, toUUID(branchless): true}, ask(nil),
		"without a default branch: main and the branchless report are trunk reports")
	assert.Equal(t, map[string]bool{toUUID(onMain): true}, ask(&main),
		"with main set: only main")

	// main once was the head of a pull request.
	mkCarryReport(t, repos, project.ID, carryReportSpec{branch: "main", base: "release/1", scope: "main-pr-scope", status: "completed"})
	assert.Equal(t, map[string]bool{toUUID(branchless): true}, ask(nil),
		"without a default branch, main is a change branch now")
	assert.Equal(t, map[string]bool{toUUID(onMain): true}, ask(&main),
		"the default branch stays the trunk")

	empty, err := port.ListFindingIDsOnTrunk(ctx, toUUID(project.ID), nil, nil)
	require.NoError(t, err)
	assert.Empty(t, empty)
}
