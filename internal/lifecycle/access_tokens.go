package lifecycle

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// AccessTokenPruner deletes one bounded batch of expired revocations.
type AccessTokenPruner interface {
	PruneExpired(context.Context) (int64, error)
}

// RunAccessTokenPrune runs one bounded sweep at startup and on every interval.
// Revocation checks ignore expired rows, so a cleanup failure changes no token's
// validity and can wait for the next sweep.
func RunAccessTokenPrune(ctx context.Context, store AccessTokenPruner, interval time.Duration, logger *slog.Logger) error {
	if interval <= 0 {
		return fmt.Errorf("access token prune interval must be positive, got %s", interval)
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			sweepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
			n, err := store.PruneExpired(sweepCtx)
			cancel()
			if err != nil && ctx.Err() == nil {
				logger.Error("access token prune failed", "error", err)
			} else if n > 0 {
				logger.Info("expired access token revocations deleted", "count", n)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}
