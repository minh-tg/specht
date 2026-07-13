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

// sweepExpiredWaivers performs a single sweep of waivers with expired
// expires_at, disabling them. It returns the expired waiver rows.
func sweepExpiredWaivers(ctx context.Context, q *sqlc.Queries, logger *slog.Logger) ([]sqlc.ExpireWaiversRow, error) {
	expired, err := q.ExpireWaivers(ctx)
	if err != nil {
		return nil, err
	}

	for _, w := range expired {
		metadata, err := json.Marshal(map[string]interface{}{
			"reason":      "waiver_expired",
			"waiver_name": w.Name,
		})
		if err != nil {
			logger.Error("marshal waiver event metadata", "error", err)
			continue
		}

		_, err = q.CreateWaiverEvent(ctx, sqlc.CreateWaiverEventParams{
			WaiverID:  w.ID,
			EventType: "auto_disabled",
			ActorID:   pgtype.Text{Valid: false},
			Metadata:  metadata,
		})
		if err != nil {
			return nil, err
		}
	}

	if len(expired) > 0 {
		logger.Info("expired waivers disabled", "count", len(expired))
	}

	return expired, nil
}

// RunWaiverExpiry starts a background goroutine that periodically sweeps
// waivers with expired expires_at, disabling them automatically.
// The goroutine stops when ctx is cancelled.
func RunWaiverExpiry(ctx context.Context, pool *pgxpool.Pool, interval time.Duration, logger *slog.Logger) {
	go func() {
		logger.Info("waiver expiry daemon started", "interval", interval)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				logger.Info("waiver expiry daemon stopped")
				return
			case <-ticker.C:
				q := sqlc.New(pool)
				_, err := sweepExpiredWaivers(context.Background(), q, logger)
				if err != nil {
					logger.Error("waiver expiry sweep failed", "error", err)
				}
			}
		}
	}()
}
