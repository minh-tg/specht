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

// pgAnalysisExpiryStore implements port.AnalysisExpiryStore. ExpireExpired
// runs one transaction that resets every expired analysis window back to
// unanalyzed/block and logs the analysis_changed event per finding, mirroring
// the original lifecycle.SweepExpiredFindings behavior.
type pgAnalysisExpiryStore struct {
	pool *pgxpool.Pool
}

// NewAnalysisExpiryStore builds the PostgreSQL analysis-expiry store.
func NewAnalysisExpiryStore(pool *pgxpool.Pool) port.AnalysisExpiryStore {
	return &pgAnalysisExpiryStore{pool: pool}
}

func (s *pgAnalysisExpiryStore) ExpireExpired(ctx context.Context) ([]port.Finding, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	q := sqlc.New(tx)
	expired, err := q.ExpireFindings(ctx)
	if err != nil {
		return nil, err
	}

	for _, f := range expired {
		changes, err := json.Marshal(map[string]map[string]string{
			"analysis_state": {"old": f.AnalysisState, "new": "unanalyzed"},
			"gate_effect":    {"old": f.GateEffect, "new": "block"},
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
// one transaction that disables every expired waiver and logs its
// auto_disabled event.
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
	defer tx.Rollback(ctx)

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
		if _, err := q.CreateWaiverEvent(ctx, sqlc.CreateWaiverEventParams{
			WaiverID:  w.ID,
			EventType: "auto_disabled",
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
