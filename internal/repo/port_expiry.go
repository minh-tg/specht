package repo

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// defaultExpiryBatchSize bounds how many findings one sweep transaction locks.
const defaultExpiryBatchSize = 500

// pgAnalysisExpiryStore implements port.AnalysisExpiryStore. ExpireExpired
// resets expired analysis windows back to unanalyzed/block in batches of
// batchSize, one short transaction per batch, and logs the
// analysis_changed event per finding. A batch skips rows another transaction
// holds, so the sweep never waits behind an ingest and never joins a lock
// cycle; skipped rows are expired by the next sweep.
type pgAnalysisExpiryStore struct {
	pool      *pgxpool.Pool
	batchSize int32
}

// NewAnalysisExpiryStore builds the PostgreSQL analysis-expiry store.
func NewAnalysisExpiryStore(pool *pgxpool.Pool) port.AnalysisExpiryStore {
	return &pgAnalysisExpiryStore{pool: pool, batchSize: defaultExpiryBatchSize}
}

func (s *pgAnalysisExpiryStore) ExpireExpired(ctx context.Context) ([]port.Finding, error) {
	var out []port.Finding
	for {
		batch, err := s.expireBatch(ctx)
		out = append(out, batch...)
		if err != nil {
			return out, err
		}
		if int32(len(batch)) < s.batchSize {
			return out, nil
		}
	}
}

func (s *pgAnalysisExpiryStore) expireBatch(ctx context.Context) ([]port.Finding, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	// Rollback is best-effort; after Commit the transaction is already closed.
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	q := sqlc.New(tx)
	expired, err := q.ExpireFindings(ctx, s.batchSize)
	if err != nil {
		return nil, err
	}

	for _, f := range expired {
		changes, err := json.Marshal(map[string]map[string]string{
			"analysis_state": {"old": f.OldAnalysisState, "new": "unanalyzed"},
			"gate_effect":    {"old": f.OldGateEffect, "new": "block"},
		})
		if err != nil {
			return nil, fmt.Errorf("marshal changes: %w", err)
		}
		if _, err := q.CreateFindingEvent(ctx, sqlc.CreateFindingEventParams{
			FindingID: f.ID,
			UserID:    pgtype.UUID{Valid: false},
			EventType: "analysis_changed",
			Comment:   pgtype.Text{String: "analysis expired, reset to unanalyzed", Valid: true},
			Changes:   changes,
		}); err != nil {
			return nil, fmt.Errorf("create event: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	out := make([]port.Finding, len(expired))
	for i, f := range expired {
		out[i] = port.Finding{
			ID:            toUUID(f.ID),
			ProjectID:     toUUID(f.ProjectID),
			AnalysisState: f.AnalysisState,
			GateEffect:    f.GateEffect,
		}
	}
	return out, nil
}

// pgWaiverExpiryStore implements port.WaiverExpiryStore. ExpireExpired runs
// one transaction that disables every expired approved waiver (auto_disabled
// event) and rejects every expired pending request (auto_rejected event).
type pgWaiverExpiryStore struct {
	pool *pgxpool.Pool
}

// NewWaiverExpiryStore builds the PostgreSQL waiver-expiry store.
func NewWaiverExpiryStore(pool *pgxpool.Pool) port.WaiverExpiryStore {
	return &pgWaiverExpiryStore{pool: pool}
}

func (s *pgWaiverExpiryStore) ExpireExpired(ctx context.Context) ([]port.Waiver, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	// Rollback is best-effort; after Commit the transaction is already closed.
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	q := sqlc.New(tx)
	expired, err := q.ExpireWaivers(ctx)
	if err != nil {
		return nil, err
	}

	for _, w := range expired {
		metadata, err := json.Marshal(map[string]any{
			"reason":      "waiver_expired",
			"waiver_name": w.Name,
		})
		if err != nil {
			return nil, fmt.Errorf("marshal waiver event metadata: %w", err)
		}
		eventType := "auto_disabled"
		if w.Status == "rejected" {
			// A request that expired before anyone decided on it.
			eventType = "auto_rejected"
		}
		if _, err := q.CreateWaiverEvent(ctx, sqlc.CreateWaiverEventParams{
			WaiverID:  w.ID,
			EventType: eventType,
			ActorID:   pgtype.Text{Valid: false},
			Metadata:  metadata,
		}); err != nil {
			return nil, fmt.Errorf("create waiver event: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit tx: %w", err)
	}

	out := make([]port.Waiver, len(expired))
	for i, w := range expired {
		out[i] = port.Waiver{
			ID:        toUUID(w.ID),
			ProjectID: toUUID(w.ProjectID),
			Name:      w.Name,
			Enabled:   false,
			UpdatedAt: time.Now(),
		}
	}
	return out, nil
}
