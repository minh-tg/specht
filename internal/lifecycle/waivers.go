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

// WaiverAnnouncer tells people about waivers a sweep found. A nil announcer sends
// nothing, and the sweep still runs.
type WaiverAnnouncer interface {
	// WaiversEnding announces approved waivers about to end.
	WaiversEnding(ctx context.Context, waivers []port.Waiver)
	// WaiversEnded announces waivers the sweep disabled.
	WaiversEnded(ctx context.Context, waivers []port.Waiver)
}

// sweepAndAnnounce runs one sweep: it disables what ended, then claims what is
// about to end. A failed claim is logged and retried on the next tick; it must not
// stop the expiry that keeps the gate honest.
func sweepAndAnnounce(ctx context.Context, store port.WaiverExpiryStore, announcer WaiverAnnouncer, warning time.Duration, logger *slog.Logger) {
	expired, err := store.ExpireExpired(ctx)
	if err != nil {
		logger.Error("waiver expiry sweep failed", "error", err)
	} else if len(expired) > 0 {
		logger.Info("expired waivers disabled", "count", len(expired))
		if announcer != nil {
			announcer.WaiversEnded(ctx, expired)
		}
	}
	if announcer == nil {
		return
	}
	ending, err := store.ClaimExpiring(ctx, time.Now().Add(warning))
	if err != nil {
		logger.Error("waiver expiry warning failed", "error", err)
		return
	}
	if len(ending) > 0 {
		announcer.WaiversEnding(ctx, ending)
	}
}

// RunWaiverExpiry starts a background goroutine that periodically sweeps
// waivers with expired expires_at, disabling them automatically. The goroutine
// stops when ctx is cancelled.
func RunWaiverExpiry(ctx context.Context, store port.WaiverExpiryStore, announcer WaiverAnnouncer, warning, interval time.Duration, logger *slog.Logger) error {
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
				sweepAndAnnounce(ctx, store, announcer, warning, logger)
			}
		}
	}()
	return nil
}
