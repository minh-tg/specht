//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/require"
)

func TestScopeSeverity_ConcurrentUpsertsKeepMaximumAndAllowDecrease(t *testing.T) {
	for _, criticalFirst := range []bool{true, false} {
		name := "medium first"
		if criticalFirst {
			name = "critical first"
		}
		t.Run(name, func(t *testing.T) { testScopeSeverityOrdering(t, criticalFirst) })
	}
}

func testScopeSeverityOrdering(t *testing.T, criticalFirst bool) {
	t.Helper()
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stores := NewPortStores(pool)
	p, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "atomic-scope", Name: "Atomic scope", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	input := port.UpsertFindingInput{
		ProjectID: p.ID, FindingKind: "sast", Fingerprint: "same-finding", Title: "Same finding",
		Severity: "medium", SeverityRank: 2, FirstSeen: time.Now(), LastSeen: time.Now(),
	}
	f, err := stores.Findings.Upsert(ctx, input)
	require.NoError(t, err)
	fid, err := parseID(f.ID)
	require.NoError(t, err)

	lock, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = lock.Rollback(context.Background()) }()
	_, err = sqlc.New(lock).LockFindingForUpdate(ctx, fid)
	require.NoError(t, err)

	results := make(chan error, 2)
	write := func(scope, severity string, rank int16) {
		in := input
		in.Severity, in.SeverityRank = severity, rank
		in.Scope = &port.FindingScopeSeverityInput{ScopeHash: scope, Severity: severity, SeverityRank: rank, ObservedAt: time.Now()}
		_, err := stores.Findings.Upsert(ctx, in)
		results <- err
	}
	waitForLocks := func(count int) {
		t.Helper()
		require.Eventually(t, func() bool {
			var waiting int
			err := pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting)
			return err == nil && waiting >= count
		}, 5*time.Second, 10*time.Millisecond)
	}
	if criticalFirst {
		go write("critical-branch", "critical", 4)
		waitForLocks(1)
		go write("medium-branch", "medium", 2)
	} else {
		go write("medium-branch", "medium", 2)
		waitForLocks(1)
		go write("critical-branch", "critical", 4)
	}
	waitForLocks(2)
	require.NoError(t, lock.Commit(ctx))
	require.NoError(t, <-results)
	require.NoError(t, <-results)

	current, err := stores.Findings.GetByID(ctx, f.ID)
	require.NoError(t, err)
	require.Equal(t, int16(4), current.CurrentSeverityRank)
	rows, err := stores.Findings.ListScopeSeverities(ctx, []string{f.ID})
	require.NoError(t, err)
	require.Len(t, rows, 2)
	blocking, err := stores.Findings.ListGateCandidates(ctx, p.ID, 3)
	require.NoError(t, err)
	require.Len(t, blocking, 1)

	// Replacing the critical scope with low must lower the aggregate to the
	// other scope's medium, rather than permanently retaining the maximum.
	write("critical-branch", "low", 1)
	require.NoError(t, <-results)
	current, err = stores.Findings.GetByID(ctx, f.ID)
	require.NoError(t, err)
	require.Equal(t, int16(2), current.CurrentSeverityRank)

	bad := input
	bad.Title, bad.Severity, bad.SeverityRank = "must roll back", "critical", 4
	bad.Scope = &port.FindingScopeSeverityInput{
		ScopeHash: "failed-scope", Severity: "critical", SeverityRank: 4,
		ReportID: "00000000-0000-0000-0000-000000000099", ObservedAt: time.Now(),
	}
	_, err = stores.Findings.Upsert(ctx, bad)
	require.Error(t, err, "a missing report must roll back the finding write too")
	current, err = stores.Findings.GetByID(ctx, f.ID)
	require.NoError(t, err)
	require.Equal(t, "Same finding", current.CurrentTitle)
	require.Equal(t, int16(2), current.CurrentSeverityRank)
}
