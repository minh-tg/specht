// Package lifecycle runs the time-based sweeps that keep findings and waivers
// current: marking findings whose analysis window expired back to unanalyzed
// and disabling waivers past their expiry. The sweepers depend only on the
// neutral port expiry stores and the caller's shutdown context — no database
// handle leaks here.
package lifecycle

import (
	"context"
	"log/slog"
	"time"

	"github.com/xMinhx/specht/internal/port"
)

// SweepExpiredFindings performs a single sweep of findings with expired
// analysis_expires_at through the store's transaction, resetting them to
// unanalyzed. It returns the number of findings that were expired.
func SweepExpiredFindings(ctx context.Context, store port.AnalysisExpiryStore, logger *slog.Logger) (int, error) {
	expired, err := store.ExpireExpired(ctx)
	if err != nil {
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
func RunAnalysisExpiry(ctx context.Context, store port.AnalysisExpiryStore, interval time.Duration, logger *slog.Logger) {
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
				if _, err := SweepExpiredFindings(ctx, store, logger); err != nil {
					logger.Error("analysis expiry sweep failed", "error", err)
				}
			}
		}
	}()
}
