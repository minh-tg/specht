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

// SweepExpiredWaivers performs a single sweep of waivers with expired
// expires_at through the store's transaction, disabling them. It returns the
// number of waivers disabled.
func SweepExpiredWaivers(ctx context.Context, store port.WaiverExpiryStore, logger *slog.Logger) (int, error) {
	expired, err := store.ExpireExpired(ctx)
	if err != nil {
		return 0, err
	}
	if len(expired) > 0 {
		logger.Info("expired waivers disabled", "count", len(expired))
	}
	return len(expired), nil
}

// RunWaiverExpiry starts a background goroutine that periodically sweeps
// waivers with expired expires_at, disabling them automatically. The goroutine
// stops when ctx is cancelled.
func RunWaiverExpiry(ctx context.Context, store port.WaiverExpiryStore, interval time.Duration, logger *slog.Logger) error {
	if interval <= 0 {
		return fmt.Errorf("waiver expiry interval must be positive, got %s", interval)
	}
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
				if _, err := SweepExpiredWaivers(ctx, store, logger); err != nil {
					logger.Error("waiver expiry sweep failed", "error", err)
				}
			}
		}
	}()
	return nil
}
