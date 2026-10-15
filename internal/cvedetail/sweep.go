package cvedetail

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// SweepRetention is how long an expired answer stays in the cache before the
// sweep deletes it. Keeping it a while lets a provider outage serve the last
// known record instead of nothing.
const SweepRetention = 30 * 24 * time.Hour

// SweepOnce deletes cache rows that expired more than SweepRetention ago.
func SweepOnce(ctx context.Context, store Store, now time.Time) (int64, error) {
	return store.Sweep(ctx, now.Add(-SweepRetention))
}

// RunSweeper sweeps once at start and then on every interval until ctx ends.
// It runs whether or not providers are configured, so rows from an earlier
// configuration still age out.
func RunSweeper(ctx context.Context, store Store, interval time.Duration, logger *slog.Logger) error {
	if interval <= 0 {
		return fmt.Errorf("cve detail sweep interval must be positive, got %s", interval)
	}
	sweep := func() {
		n, err := SweepOnce(ctx, store, time.Now())
		if err != nil && ctx.Err() == nil {
			logger.Error("cve detail cache sweep failed", "error", err)
			return
		}
		if n > 0 {
			logger.Info("cve detail cache rows removed", "count", n)
		}
	}
	go func() {
		sweep()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweep()
			}
		}
	}()
	return nil
}
