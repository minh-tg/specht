package usecase

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/minh-tg/specht/internal/port"
)

// WatcherStatusResponse reports the CVE watcher daemon's health so operators
// can tell a working watcher from a failed or stale one.
type WatcherStatusResponse struct {
	// LastSuccessfulPollAt is when the last fully successful poll finished,
	// or zero when no poll has ever completed (cold start).
	LastSuccessfulPollAt string `json:"last_successful_poll_at,omitempty"`
	// LastPollAttemptAt is when the most recent poll attempt started.
	LastPollAttemptAt string `json:"last_poll_attempt_at,omitempty"`
	// LastError is the most recent poll failure text, empty when healthy.
	LastError string `json:"last_error,omitempty"`
	// ConsecutiveFailures is how many polls have failed in a row.
	ConsecutiveFailures int32 `json:"consecutive_failures"`
	// Healthy is true when the watcher has no recorded failure state AND its
	// last successful poll is not stale (older than the staleness window).
	Healthy bool `json:"healthy"`
	// Stale is true when the last successful poll is older than the
	// staleness window (the daemon may be down or wedged). A stale watcher
	// must never be mistaken for clean.
	Stale bool `json:"stale"`
	// StalenessWindow is the configured window beyond which a watcher with
	// no recent successful poll is considered stale.
	StalenessWindow string `json:"staleness_window,omitempty"`
}

// watcherStalenessWindow resolves the staleness threshold: WATCHER_POLL_INTERVAL
// (the daemon's cadence) if set, else the 6h default. A watcher whose last
// successful poll is older than 2x the cadence is stale.
func watcherStalenessWindow() time.Duration {
	const defaultInterval = 6 * time.Hour
	interval := defaultInterval
	if v := os.Getenv("WATCHER_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			interval = d
		}
	}
	return 2 * interval
}

func (u *Usecases) GetWatcherStatus(ctx context.Context) (*WatcherStatusResponse, error) {
	st, err := u.deps.Stores.Watcher.GetState(ctx)
	if errors.Is(err, port.ErrNotFound) {
		// No poll ever recorded: cold start, not a failure.
		return &WatcherStatusResponse{Healthy: true}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get watcher state: %w", err)
	}
	return watcherStatusFromState(st), nil
}

func watcherStatusFromState(st port.WatcherState) *WatcherStatusResponse {
	window := watcherStalenessWindow()
	resp := &WatcherStatusResponse{
		ConsecutiveFailures: st.ConsecutiveFailures,
		StalenessWindow:     window.String(),
	}
	if st.LastSuccessfulPollAt != nil {
		resp.LastSuccessfulPollAt = st.LastSuccessfulPollAt.UTC().Format(time.RFC3339)
		resp.Stale = time.Since(*st.LastSuccessfulPollAt) > window
	} else if st.LastPollAttemptAt != nil {
		resp.Stale = time.Since(*st.LastPollAttemptAt) > window
	}
	if st.LastPollAttemptAt != nil {
		resp.LastPollAttemptAt = st.LastPollAttemptAt.UTC().Format(time.RFC3339)
	}
	if st.LastError != nil {
		resp.LastError = *st.LastError
	}
	resp.Healthy = !resp.Stale && (st.LastError == nil || *st.LastError == "")
	return resp
}
