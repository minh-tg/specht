package lifecycle

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// RawPayloadClearer clears raw_data payloads. The report store implements it.
type RawPayloadClearer interface {
	ClearRawData(ctx context.Context, cutoff time.Time, batchSize int32) (int64, error)
}

// rawRetentionBatch bounds how many payloads one statement clears, so a backlog after a window
// change is worked off in short transactions instead of one long lock on reports.
const rawRetentionBatch = 100

// ClearExpiredRaw clears the raw_data payload of every settled report older than the window,
// in batches, and returns how many it cleared. A window of zero keeps every payload and does
// nothing. Only the count is logged, never the payload.
func ClearExpiredRaw(ctx context.Context, store RawPayloadClearer, days int, now time.Time, logger *slog.Logger) (int64, error) {
	if days == 0 {
		return 0, nil
	}
	cutoff := now.Add(-time.Duration(days) * 24 * time.Hour)
	var total int64
	for {
		n, err := store.ClearRawData(ctx, cutoff, rawRetentionBatch)
		if err != nil {
			return total, err
		}
		total += n
		if n < rawRetentionBatch || ctx.Err() != nil {
			break
		}
	}
	if total > 0 {
		logger.Info("raw report payloads cleared", "count", total, "retention_days", days)
	}
	return total, ctx.Err()
}

// RunRawRetention clears expired raw payloads once at start and then on every interval until ctx
// is cancelled. It runs on the lifecycle sweep interval. A window of zero starts nothing.
func RunRawRetention(ctx context.Context, store RawPayloadClearer, interval time.Duration, days int, logger *slog.Logger) error {
	if days < 0 {
		return fmt.Errorf("raw retention days must be zero or more, got %d", days)
	}
	if days == 0 {
		logger.Info("raw report retention disabled", "retention_days", 0)
		return nil
	}
	if interval <= 0 {
		return fmt.Errorf("raw retention interval must be positive, got %s", interval)
	}
	sweep := func() {
		if _, err := ClearExpiredRaw(ctx, store, days, time.Now(), logger); err != nil && ctx.Err() == nil {
			logger.Error("raw retention sweep failed", "error", err)
		}
	}
	go func() {
		logger.Info("raw retention sweeper started", "interval", interval, "retention_days", days)
		sweep()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				logger.Info("raw retention sweeper stopped")
				return
			case <-ticker.C:
				sweep()
			}
		}
	}()
	return nil
}
