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

// watcherStalenessWindow resolves the staleness threshold: twice the longest gap
// the daemon may leave between polls. That is WATCHER_POLL_INTERVAL (6h by default)
// or the longest interval of a project with the watcher on, whichever is longer:
// nothing is polled until a project is due, so a window shorter than every project's
// interval calls a working watcher stale.
func watcherStalenessWindow(projects []port.Project) time.Duration {
	const defaultInterval = 6 * time.Hour
	interval := defaultInterval
	if v := os.Getenv("WATCHER_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			interval = d
		}
	}
	for _, p := range projects {
		if p.CveWatcherEnabled {
			interval = max(interval, time.Duration(p.CveWatcherIntervalSecs)*time.Second)
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
	projects, err := u.deps.Stores.Projects.List(ctx)
	if err != nil {
		return nil, fmt.Errorf("list projects for watcher status: %w", err)
	}
	return watcherStatusFromState(st, watcherStalenessWindow(projects)), nil
}

func watcherStatusFromState(st port.WatcherState, window time.Duration) *WatcherStatusResponse {
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
