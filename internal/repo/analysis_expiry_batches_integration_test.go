//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func upsertSCAFindings(t *testing.T, ctx context.Context, stores *port.Stores, projectID string, fingerprints ...string) {
	t.Helper()
	now := time.Now().UTC()
	for _, fp := range fingerprints {
		_, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
			ProjectID: projectID, FindingKind: "sca", Fingerprint: fp, Title: fp,
			Severity: "high", SeverityRank: 3, FirstSeen: now, LastSeen: now,
		})
		require.NoError(t, err)
	}
}

func markAnalysisExpired(t *testing.T, ctx context.Context, repos *Repos, projectID string) {
	t.Helper()
	_, err := repos.pool.Exec(ctx, `UPDATE findings SET analysis_state = 'accepted_risk', gate_effect = 'ignore',
		analysis_expires_at = NOW() - INTERVAL '1 hour' WHERE project_id = $1`, mustParseID(projectID))
	require.NoError(t, err)
}

func countPendingExpiry(t *testing.T, ctx context.Context, repos *Repos) int {
	t.Helper()
	var n int
	require.NoError(t, repos.pool.QueryRow(ctx,
		`SELECT count(*) FROM findings WHERE analysis_expires_at IS NOT NULL AND analysis_expires_at <= NOW()`).Scan(&n))
	return n
}

// The ingest upserts f2 then f1 while the sweep scans f1 then f2. A sweep that
// waits for rows an ingest holds forms a lock cycle with it; the batched sweep
// skips held rows, so neither side is aborted and the next sweep finishes.
func TestAnalysisExpirySweepDoesNotDeadlockWithIngest(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	project := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()

	upsertSCAFindings(t, ctx, stores, projectID, "f1", "f2")
	markAnalysisExpired(t, ctx, repos, projectID)

	sweepStore := NewAnalysisExpiryStore(repos.pool)
	swept := make(chan error, 1)
	ingestErr := stores.Ingest.Run(ctx, projectID, port.IngestCaller{}, func(s *port.Stores) error {
		upsertSCAFindings(t, ctx, s, projectID, "f2")
		go func() {
			_, err := sweepStore.ExpireExpired(ctx)
			swept <- err
		}()
		time.Sleep(300 * time.Millisecond)
		upsertSCAFindings(t, ctx, s, projectID, "f1")
		return nil
	})
	sweepErr := <-swept

	require.False(t, isDeadlock(ingestErr), "ingest aborted by a deadlock: %v", ingestErr)
	require.False(t, isDeadlock(sweepErr), "sweep aborted by a deadlock: %v", sweepErr)
	require.NoError(t, ingestErr)
	require.NoError(t, sweepErr)

	// Whatever the sweep skipped is expired by the next run.
	_, err := sweepStore.ExpireExpired(ctx)
	require.NoError(t, err)
	require.Zero(t, countPendingExpiry(t, ctx, repos))
}

// A row another transaction holds is skipped, not waited for, and expired by
// the next sweep.
func TestAnalysisExpirySweepSkipsLockedRowsAndFinishesLater(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	project := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()

	upsertSCAFindings(t, ctx, stores, projectID, "held", "free")
	markAnalysisExpired(t, ctx, repos, projectID)

	tx, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SELECT id FROM findings WHERE project_id = $1 AND fingerprint = 'held' FOR UPDATE`, mustParseID(projectID))
	require.NoError(t, err)

	sweepStore := NewAnalysisExpiryStore(repos.pool)
	sweepCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	done, err := sweepStore.ExpireExpired(sweepCtx)
	require.NoError(t, err, "the sweep must not wait for the held row")
	require.Len(t, done, 1)
	require.Equal(t, 1, countPendingExpiry(t, ctx, repos))

	require.NoError(t, tx.Rollback(ctx))
	done, err = sweepStore.ExpireExpired(ctx)
	require.NoError(t, err)
	require.Len(t, done, 1)
	require.Zero(t, countPendingExpiry(t, ctx, repos))
}

// More expired rows than one batch holds are all expired in one call, each
// batch in its own transaction.
func TestAnalysisExpirySweepExpiresEveryBatch(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	project := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()

	fingerprints := []string{"a", "b", "c", "d", "e", "f", "g"}
	upsertSCAFindings(t, ctx, stores, projectID, fingerprints...)
	markAnalysisExpired(t, ctx, repos, projectID)

	store := &pgAnalysisExpiryStore{pool: repos.pool, batchSize: 3}
	done, err := store.ExpireExpired(ctx)
	require.NoError(t, err)
	require.Len(t, done, len(fingerprints))
	require.Zero(t, countPendingExpiry(t, ctx, repos))

	var events int
	require.NoError(t, repos.pool.QueryRow(ctx,
		`SELECT count(*) FROM finding_events WHERE event_type = 'analysis_changed'`).Scan(&events))
	require.Equal(t, len(fingerprints), events)
}
