// Package lifecycle runs the time-based sweeps that keep findings and waivers
// current: marking findings whose analysis window expired back to unanalyzed
// and disabling waivers past their expiry. The sweepers depend only on the
// neutral port expiry stores and the caller's shutdown context — no database
// handle leaks here.
package lifecycle

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/minh-tg/specht/internal/port"
)

// SweepExpiredFindings performs a single sweep of findings with expired
// analysis_expires_at through the store's transaction, resetting them to
// unanalyzed. It returns the number of findings that were expired.
func SweepExpiredFindings(ctx context.Context, store port.AnalysisExpiryStore, logger *slog.Logger) (int, error) {
	expired, err := store.ExpireExpired(ctx)
	if err != nil {
		return len(expired), err
	}
	if len(expired) > 0 {
		logger.Info("expired findings reset", "count", len(expired))
	}
	return len(expired), nil
}

// analysisSweepTimeout caps one sweep. Batches that committed before the cap
// stay committed; the next sweep continues with the rest.
const analysisSweepTimeout = 2 * time.Minute

// RunAnalysisExpiry starts a background goroutine that periodically sweeps
// findings with expired analysis_expires_at, resetting them to unanalyzed.
// The goroutine stops when ctx is cancelled.
func RunAnalysisExpiry(ctx context.Context, store port.AnalysisExpiryStore, interval time.Duration, logger *slog.Logger) error {
	if interval <= 0 {
		return fmt.Errorf("analysis expiry interval must be positive, got %s", interval)
	}
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
				sweepCtx, cancel := context.WithTimeout(ctx, analysisSweepTimeout)
				_, err := SweepExpiredFindings(sweepCtx, store, logger)
				cancel()
				if err != nil {
					logger.Error("analysis expiry sweep failed", "error", err)
				}
			}
		}
	}()
	return nil
}
