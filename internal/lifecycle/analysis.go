package lifecycle

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

// SweepExpiredFindings performs a single sweep of findings with expired
// analysis_expires_at, resetting them to unanalyzed. It returns the number
// of findings that were expired.
func SweepExpiredFindings(ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger) (int, error) {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback(ctx)

	q := sqlc.New(tx)

	expired, err := q.ExpireFindings(ctx)
	if err != nil {
		return 0, err
	}

	for _, f := range expired {
		changes, err := json.Marshal(map[string]map[string]string{
			"analysis_state": {"old": f.AnalysisState, "new": "unanalyzed"},
			"gate_effect":    {"old": f.GateEffect, "new": "block"},
		})
		if err != nil {
			logger.Error("marshal changes", "error", err)
			continue
		}

		_, err = q.CreateFindingEvent(ctx, sqlc.CreateFindingEventParams{
			FindingID: f.ID,
			UserID:    pgtype.UUID{Valid: false},
			EventType: "analysis_changed",
			OldValue:  pgtype.Text{Valid: false},
			NewValue:  pgtype.Text{Valid: false},
			Comment:   pgtype.Text{String: "analysis expired, reset to unanalyzed", Valid: true},
			Changes:   changes,
		})
		if err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}

	if len(expired) > 0 {
		logger.Info("expired findings reset", "count", len(expired))
	}

	return len(expired), nil
}

// RunAnalysisExpiry starts a background goroutine that periodically sweeps
// findings with expired analysis_expires_at, resetting them to unanalyzed.
// The goroutine stops when ctx is cancelled.
func RunAnalysisExpiry(ctx context.Context, pool *pgxpool.Pool, interval time.Duration, logger *slog.Logger) {
	go func() {
		logger.Info("analysis expiry daemon started", "interval", interval)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				logger.Info("analysis expiry daemon stopped")
				return
			case <-ticker.C:
				_, err := SweepExpiredFindings(context.Background(), pool, logger)
				if err != nil {
					logger.Error("analysis expiry sweep failed", "error", err)
				}
			}
		}
	}()
}
