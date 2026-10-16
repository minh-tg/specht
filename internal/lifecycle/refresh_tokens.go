package lifecycle

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

const (
	// RefreshRevokedRetention is how long a revoked refresh token row is kept.
	// Reuse detection needs the row of a rotated token, and a replay a week
	// later is no longer worth acting on.
	RefreshRevokedRetention = 7 * 24 * time.Hour
	// RefreshPruneBatch caps the rows one delete removes, so a large backlog
	// never holds a long lock on the table.
	RefreshPruneBatch = 1000
	// RefreshPruneMaxBatches caps the deletes one sweep runs. The rest waits
	// for the next sweep.
	RefreshPruneMaxBatches = 50
)

// RefreshTokenPruner deletes dead refresh token rows.
type RefreshTokenPruner interface {
	// Prune deletes up to limit rows that expired before expiredBefore or were
	// revoked before revokedBefore, and returns how many it deleted.
	Prune(ctx context.Context, expiredBefore, revokedBefore time.Time, limit int) (int64, error)
}

// PruneRefreshTokens deletes refresh tokens that are expired, or revoked more
// than RefreshRevokedRetention ago, in batches of RefreshPruneBatch. It stops
// at the first short batch or after RefreshPruneMaxBatches, and returns how
// many rows it deleted (also when it stops on an error).
func PruneRefreshTokens(ctx context.Context, store RefreshTokenPruner, now time.Time, logger *slog.Logger) (int, error) {
	total := 0
	for i := 0; i < RefreshPruneMaxBatches; i++ {
		n, err := store.Prune(ctx, now, now.Add(-RefreshRevokedRetention), RefreshPruneBatch)
		total += int(n)
		if err != nil {
			return total, err
		}
		if n < RefreshPruneBatch {
			break
		}
	}
	if total > 0 {
		logger.Info("dead refresh tokens deleted", "count", total)
	}
	return total, nil
}

// RunRefreshTokenPrune sweeps once at start, which clears what built up while
// the server was down, and then on every interval until ctx is cancelled.
func RunRefreshTokenPrune(ctx context.Context, store RefreshTokenPruner, interval time.Duration, logger *slog.Logger) error {
	if interval <= 0 {
		return fmt.Errorf("refresh token prune interval must be positive, got %s", interval)
	}
	sweep := func() {
		if _, err := PruneRefreshTokens(ctx, store, time.Now(), logger); err != nil && ctx.Err() == nil {
			logger.Error("refresh token prune failed", "error", err)
		}
	}
	go func() {
		logger.Info("refresh token prune started", "interval", interval)
		sweep()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				logger.Info("refresh token prune stopped")
				return
			case <-ticker.C:
				sweep()
			}
		}
	}()
	return nil
}
