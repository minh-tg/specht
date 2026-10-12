//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
)

// TestOpenDefinition_StatsGateAndAgingAgree seeds a project with every kind of
// finding that could make the three surfaces disagree and checks that they
// report the same open and blocking numbers: fixed, ignored, below the policy
// floor, waived and plainly blocking.
func TestOpenDefinition_StatsGateAndAgingAgree(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()

	stores := NewPortStores(pool)
	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		require.NoError(t, reg.Register(s))
	}
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: reg})

	creator, err := stores.Users.Create(ctx, "tester@example.com", nil, nil)
	require.NoError(t, err)
	admin := globalAdminCtx(creator.ID)
	_, err = uc.CreateProject(admin, "My App", "my-app", "agreement", creator.ID)
	require.NoError(t, err)
	project, err := stores.Projects.GetBySlug(ctx, "my-app")
	require.NoError(t, err)

	now := time.Now().UTC()
	seed := func(fp, severity string, rank int16, daysAgo int) string {
		t.Helper()
		ts := now.AddDate(0, 0, -daysAgo)
		f, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
			ProjectID: project.ID, FindingKind: "sca", Fingerprint: fp, Title: fp,
			Severity: severity, SeverityRank: rank, Score: 5.0, FirstSeen: ts, LastSeen: now,
		})
		require.NoError(t, err)
		return f.ID
	}
	exec := func(query string, args ...any) {
		t.Helper()
		_, err := pool.Exec(ctx, query, args...)
		require.NoError(t, err)
	}

	seed("critical-blocks", "critical", 4, 30)
	seed("high-blocks", "high", 3, 5)
	reopened := seed("high-reopened", "high", 3, 50)
	waived := seed("critical-waived", "critical", 4, 10)
	ignored := seed("high-ignored", "high", 3, 20)
	seed("medium-below-floor", "medium", 2, 200)
	seed("low-below-floor", "low", 1, 3)
	fixed := seed("critical-fixed", "critical", 4, 400)

	exec(`UPDATE findings SET state = 'reopened' WHERE id = $1`, reopened)
	exec(`UPDATE findings SET state = 'fixed', fixed_at = NOW() WHERE id = $1`, fixed)
	exec(`UPDATE findings SET analysis_state = 'false_positive', gate_effect = 'ignore' WHERE id = $1`, ignored)
	_, err = uc.CreateWaiver(admin, usecase.CreateWaiverInput{
		ProjectSlug: "my-app", Name: "accepted", TargetIDs: []string{waived}, ActorID: creator.ID,
	})
	require.NoError(t, err)

	gateStatus, err := uc.GetGateStatus(admin, "my-app", 0)
	require.NoError(t, err)
	stats, err := uc.GetProjectStats(admin, "my-app")
	require.NoError(t, err)
	agingResp, err := uc.GetAging(admin, "my-app")
	require.NoError(t, err)

	// Open: everything except the fixed finding.
	const open = 7
	assert.EqualValues(t, open, stats.TotalFindings)
	var byState int32
	for _, s := range stats.ByAnalysisState {
		byState += s.Count
	}
	assert.EqualValues(t, open, byState, "analysis states cover the same open findings")
	var agingTotal int32
	for _, b := range agingResp.Buckets {
		agingTotal += b.Count
	}
	assert.EqualValues(t, open, agingTotal, "aging buckets cover the same open findings")
	assert.False(t, agingResp.Truncated)

	// Blocking: critical-blocks, high-blocks and high-reopened. The waived one,
	// the ignored one, the two below the floor and the fixed one do not block.
	assert.EqualValues(t, 3, gateStatus.BlockingCount)
	assert.EqualValues(t, gateStatus.BlockingCount, stats.BlockingCount, "stats and the gate count the same blockers")
	var bySeverity int32
	for _, s := range stats.BySeverity {
		bySeverity += s.BlockingCount
	}
	assert.EqualValues(t, stats.BlockingCount, bySeverity, "the per-severity blocking numbers add up")
	blocking := map[string]int32{}
	for _, s := range stats.BySeverity {
		blocking[s.Severity] = s.BlockingCount
	}
	assert.EqualValues(t, 1, blocking["critical"])
	assert.EqualValues(t, 2, blocking["high"])
	assert.EqualValues(t, 0, blocking["medium"])
	assert.EqualValues(t, 0, blocking["low"])

	// The weekly trend counts every finding first seen in the 12-week window,
	// whatever its state today. Six of the eight qualify; the 400-day-old fixed
	// one and the 200-day-old medium one are outside it.
	var trend int32
	for _, w := range agingResp.NewPerWeek {
		trend += w.Count
	}
	assert.EqualValues(t, 6, trend)
}

func TestAgingRows_TruncatesAtTheCapAndSaysSo(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "big", Name: "Big", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `INSERT INTO findings (project_id, finding_kind, fingerprint, current_title, current_severity, current_severity_rank, first_seen_at)
		SELECT $1, 'sca', 'fp-' || g, 'f' || g, 'high', 3, NOW() - (g || ' minutes')::interval
		FROM generate_series(1, $2) AS g`, project.ID, port.MaxAgingRows+5)
	require.NoError(t, err)
	// Closed findings take no part in the cap.
	_, err = pool.Exec(ctx, `INSERT INTO findings (project_id, finding_kind, fingerprint, current_title, current_severity, current_severity_rank, state)
		SELECT $1, 'sca', 'fixed-' || g, 'x' || g, 'high', 3, 'fixed' FROM generate_series(1, 20) AS g`, project.ID)
	require.NoError(t, err)

	rows, truncated, err := stores.Stats.GetAgingRows(ctx, project.ID)
	require.NoError(t, err)
	assert.True(t, truncated)
	assert.Len(t, rows, port.MaxAgingRows)
	assert.True(t, rows[0].FirstSeen.Before(rows[len(rows)-1].FirstSeen), "the oldest findings are the ones kept")
	for _, r := range rows[:3] {
		assert.Equal(t, "open", r.State)
	}
}
