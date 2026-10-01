//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// TestStatsRepo_AnalysisStateCounts verifies the per-analysis-state roll-up:
// every state with open or reopened findings is reported once, ordered by
// state name, findings already fixed are left out (the scan that fixed them
// never touches their analysis state, so they would otherwise read as
// untriaged work forever), and the null/empty state the schema cannot normally
// hold folds into unanalyzed.
func TestStatsRepo_AnalysisStateCounts(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()

	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "stats-state", Name: "Stats State",
		DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)

	empty, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "stats-state-empty", Name: "Stats State Empty",
		DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)

	now := time.Now().UTC()
	seed := func(fp string) {
		_, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
			ProjectID: project.ID, FindingKind: "sca", Fingerprint: fp, Title: fp,
			Severity: "high", SeverityRank: 3, Score: 7.0,
			FirstSeen: now, LastSeen: now,
		})
		require.NoError(t, err)
	}
	seed("fp-null")
	seed("fp-empty")
	seed("fp-exploitable")
	seed("fp-false-positive")
	seed("fp-fixed")
	seed("fp-reopened")

	// The schema defaults analysis_state to unanalyzed and rejects null and
	// empty values. Relax both in the throwaway test database to exercise the
	// count query's normalization of either into unanalyzed.
	_, err = pool.Exec(ctx, `ALTER TABLE findings ALTER COLUMN analysis_state DROP NOT NULL`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_analysis_state_check`)
	require.NoError(t, err)

	setState := func(fp string, state *string) {
		tag, err := pool.Exec(ctx,
			`UPDATE findings SET analysis_state = $1 WHERE project_id = $2 AND fingerprint = $3`,
			state, project.ID, fp)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected())
	}
	setState("fp-null", nil)
	setState("fp-empty", strPtr(""))
	setState("fp-exploitable", strPtr("exploitable"))
	setState("fp-false-positive", strPtr("false_positive"))
	setState("fp-reopened", strPtr("exploitable"))

	setFindingState := func(fp, state string) {
		tag, err := pool.Exec(ctx,
			`UPDATE findings SET state = $1 WHERE project_id = $2 AND fingerprint = $3`,
			state, project.ID, fp)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected())
	}
	// A finding the scanner stopped reporting is marked fixed and keeps its
	// unanalyzed analysis state; a reopened one is active work again.
	setFindingState("fp-fixed", "fixed")
	setFindingState("fp-reopened", "reopened")

	counts, err := stores.Stats.GetProjectAnalysisStateCounts(ctx, project.ID)
	require.NoError(t, err)
	assert.Equal(t, []port.AnalysisStateStat{
		{State: "exploitable", Count: 2},
		{State: "false_positive", Count: 1},
		{State: "unanalyzed", Count: 2},
	}, counts)

	none, err := stores.Stats.GetProjectAnalysisStateCounts(ctx, empty.ID)
	require.NoError(t, err)
	assert.NotNil(t, none, "a project without findings reports an empty array, never null")
	assert.Empty(t, none)
}

// TestStatsRepo_SeverityCountsLeaveOutFixed verifies that the per-severity
// roll-up (and so the project's total and blocking counts) covers open and
// reopened findings only. A finding the scanner stopped reporting is marked
// fixed and must not keep counting toward the project's findings.
func TestStatsRepo_SeverityCountsLeaveOutFixed(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()

	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "stats-severity", Name: "Stats Severity",
		DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)

	now := time.Now().UTC()
	seed := func(fp, severity string, rank int16) {
		_, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
			ProjectID: project.ID, FindingKind: "sca", Fingerprint: fp, Title: fp,
			Severity: severity, SeverityRank: rank, Score: 5.0,
			FirstSeen: now, LastSeen: now,
		})
		require.NoError(t, err)
	}
	seed("fp-open-high", "high", 3)
	seed("fp-fixed-critical", "critical", 4)
	seed("fp-reopened-low", "low", 1)
	seed("fp-fixed-high", "high", 3)
	seed("fp-open-unknown", "unknown", 0)

	setFindingState := func(fp, state string) {
		tag, err := pool.Exec(ctx,
			`UPDATE findings SET state = $1 WHERE project_id = $2 AND fingerprint = $3`,
			state, project.ID, fp)
		require.NoError(t, err)
		require.EqualValues(t, 1, tag.RowsAffected())
	}
	setFindingState("fp-fixed-critical", "fixed")
	setFindingState("fp-fixed-high", "fixed")
	setFindingState("fp-reopened-low", "reopened")

	rows, err := stores.Stats.GetProjectStats(ctx, project.ID)
	require.NoError(t, err)
	assert.ElementsMatch(t, []port.SeverityStat{
		{Severity: "high", Count: 1, BlockingCount: 1},
		{Severity: "low", Count: 1, BlockingCount: 1},
		{Severity: "unknown", Count: 1, BlockingCount: 1},
	}, rows, "fixed findings are left out; open and reopened ones stay")
}
