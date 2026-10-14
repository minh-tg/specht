package lifecycle

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// StaleReportReason is the error message a stranded report is settled with.
const StaleReportReason = "Interrupted: the server stopped before this report finished. Upload the scan again."

// ReportReaper settles reports an ingest left in processing.
type ReportReaper interface {
	FailStale(ctx context.Context, cutoff time.Time, reason string) (int64, error)
}

// ReapStaleReports settles every report that has been processing for longer than olderThan as
// failed and returns how many it changed. A report stays in processing only while its ingest
// request runs, so one this old belongs to a server that stopped under it.
func ReapStaleReports(ctx context.Context, store ReportReaper, olderThan time.Duration, logger *slog.Logger) (int, error) {
	n, err := store.FailStale(ctx, time.Now().Add(-olderThan), StaleReportReason)
	if err != nil {
		return 0, err
	}
	if n > 0 {
		logger.Warn("reports stuck in processing were marked failed", "count", n)
	}
	return int(n), nil
}

// RunStaleReportReaper sweeps once at once, which settles what a crash stranded as soon as the
// server is back, and then on every interval until ctx is cancelled.
func RunStaleReportReaper(ctx context.Context, store ReportReaper, interval, olderThan time.Duration, logger *slog.Logger) error {
	if interval <= 0 {
		return fmt.Errorf("stale report sweep interval must be positive, got %s", interval)
	}
	if olderThan <= 0 {
		return fmt.Errorf("stale report age must be positive, got %s", olderThan)
	}
	sweep := func() {
		if _, err := ReapStaleReports(ctx, store, olderThan, logger); err != nil && ctx.Err() == nil {
			logger.Error("stale report sweep failed", "error", err)
		}
	}
	go func() {
		logger.Info("stale report reaper started", "interval", interval, "older_than", olderThan)
		sweep()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				logger.Info("stale report reaper stopped")
				return
			case <-ticker.C:
				sweep()
			}
		}
	}()
	return nil
}
