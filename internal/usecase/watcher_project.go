package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/minh-tg/specht/internal/port"
)

const (
	// defaultProjectWatcherInterval is the interval new projects start with
	// (migration 000020) and the value a reset returns to.
	defaultProjectWatcherInterval = time.Hour
	// maxProjectWatcherInterval keeps a project from going silent for so long
	// that nobody notices.
	maxProjectWatcherInterval = 7 * 24 * time.Hour
	// watcherStaleGrace is added to twice the interval before a project's last
	// poll counts as stale, so a slow round does not flap the status.
	watcherStaleGrace = 5 * time.Minute
)

// ErrInvalidWatcherSettings is returned for a watcher setting outside the
// allowed range or a request that changes nothing. Handlers map it to a 400.
var ErrInvalidWatcherSettings = errors.New("invalid watcher settings")

// WatcherSettings is the server-wide CVE watcher configuration.
type WatcherSettings struct {
	// Enabled is whether this server runs the watcher at all.
	Enabled bool
	// PollInterval is the operator's polling cadence.
	PollInterval time.Duration
}

// minProjectInterval is the shortest interval a project may ask for: the
// operator's poll interval, but never above the default, so the default every
// project starts with stays valid however slowly the operator polls.
func (s WatcherSettings) minProjectInterval() time.Duration {
	if s.PollInterval > 0 && s.PollInterval < defaultProjectWatcherInterval {
		return s.PollInterval
	}
	return defaultProjectWatcherInterval
}

// Watcher health states of one project.
const (
	WatcherStatusDisabled  = "disabled"   // switched off for this project
	WatcherStatusServerOff = "server_off" // the server does not run the watcher
	WatcherStatusWaiting   = "waiting"    // on, but no poll has finished yet
	WatcherStatusOK        = "ok"
	WatcherStatusStale     = "stale"   // the last poll is older than the interval explains
	WatcherStatusFailing   = "failing" // the watcher's recent polls are failing
)

// ProjectWatcherResponse is one project's watcher configuration with what
// actually happens because of it.
type ProjectWatcherResponse struct {
	// Enabled and IntervalSeconds are the project's own settings.
	Enabled         bool  `json:"enabled"`
	IntervalSeconds int32 `json:"interval_seconds"`
	// The accepted range, and the value a reset returns to.
	DefaultIntervalSeconds int32 `json:"default_interval_seconds"`
	MinIntervalSeconds     int32 `json:"min_interval_seconds"`
	MaxIntervalSeconds     int32 `json:"max_interval_seconds"`
	// ServerEnabled is whether the server runs the watcher. A project can be
	// switched on while the server has it off; the setting waits.
	ServerEnabled bool `json:"server_enabled"`
	// EffectiveEnabled and EffectiveIntervalSeconds are what the watcher does.
	EffectiveEnabled         bool  `json:"effective_enabled"`
	EffectiveIntervalSeconds int32 `json:"effective_interval_seconds"`
	// LastPollAt is when the project's last poll finished, absent before the first.
	LastPollAt string `json:"last_poll_at,omitempty"`
	// Status says in one word why the project is or is not being polled.
	Status string `json:"status"`
	// Healthy is false when the status is stale or failing.
	Healthy bool `json:"healthy"`
}

// WatcherSettingsInput is a change to a project's watcher settings. Nil
// fields stay as they are.
type WatcherSettingsInput struct {
	Enabled *bool
	// IntervalSeconds sets the interval.
	IntervalSeconds *int32
	// ResetInterval returns the interval to the default.
	ResetInterval bool
}

// projectWatcherStatus derives one project's status from its own poll state.
// Failing comes from the project's failure counter, not the global one: the
// daemon keeps the global counter up while any project fails, so reading it
// here marked every project failing because of one.
func projectWatcherStatus(cfg WatcherSettings, enabled bool, interval time.Duration, state port.WatcherProjectState, now time.Time) string {
	lastPoll := state.LastSuccessfulPollAt
	switch {
	case !enabled:
		return WatcherStatusDisabled
	case !cfg.Enabled:
		return WatcherStatusServerOff
	case state.ConsecutiveFailures > 0:
		return WatcherStatusFailing
	case lastPoll == nil:
		return WatcherStatusWaiting
	case now.Sub(*lastPoll) > 2*interval+watcherStaleGrace:
		return WatcherStatusStale
	default:
		return WatcherStatusOK
	}
}

func (u *Usecases) projectWatcherResponse(ctx context.Context, p port.Project, now time.Time) (*ProjectWatcherResponse, error) {
	cfg := u.deps.Watcher
	interval := time.Duration(p.CveWatcherIntervalSecs) * time.Second
	if interval <= 0 {
		interval = cfg.PollInterval
	}
	if interval <= 0 {
		interval = defaultProjectWatcherInterval
	}

	state, err := u.deps.Stores.Watcher.GetProjectState(ctx, p.ID)
	switch {
	case err == nil:
	case errors.Is(err, port.ErrNotFound):
		state = port.WatcherProjectState{}
	default:
		return nil, fmt.Errorf("get project watcher state: %w", err)
	}
	lastPoll := state.LastSuccessfulPollAt

	status := projectWatcherStatus(cfg, p.CveWatcherEnabled, interval, state, now)
	resp := &ProjectWatcherResponse{
		Enabled:                  p.CveWatcherEnabled,
		IntervalSeconds:          p.CveWatcherIntervalSecs,
		DefaultIntervalSeconds:   int32(defaultProjectWatcherInterval / time.Second),
		MinIntervalSeconds:       int32(cfg.minProjectInterval() / time.Second),
		MaxIntervalSeconds:       int32(maxProjectWatcherInterval / time.Second),
		ServerEnabled:            cfg.Enabled,
		EffectiveEnabled:         p.CveWatcherEnabled && cfg.Enabled,
		EffectiveIntervalSeconds: int32(interval / time.Second),
		Status:                   status,
		Healthy:                  status != WatcherStatusStale && status != WatcherStatusFailing,
	}
	if lastPoll != nil {
		resp.LastPollAt = lastPoll.UTC().Format(time.RFC3339)
	}
	return resp, nil
}

// GetProjectWatcher returns a project's watcher settings and status. Any
// project member may read it.
func (u *Usecases) GetProjectWatcher(ctx context.Context, projectSlug string) (*ProjectWatcherResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectMember(ctx, project.ID); err != nil {
		return nil, err
	}
	config, err := u.deps.Stores.Watcher.GetProjectConfig(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get project watcher config: %w", err)
	}
	return u.projectWatcherResponse(ctx, config, now())
}

// UpdateProjectWatcher changes a project's watcher settings. The interval
// must lie between the server's floor and seven days. Switching a project on
// while the server has the watcher off is allowed and stored; the response
// says it is not in effect. Needs the project admin role.
func (u *Usecases) UpdateProjectWatcher(ctx context.Context, projectSlug string, in WatcherSettingsInput) (*ProjectWatcherResponse, error) {
	if in.Enabled == nil && in.IntervalSeconds == nil && !in.ResetInterval {
		return nil, fmt.Errorf("%w: nothing to change", ErrInvalidWatcherSettings)
	}
	if in.IntervalSeconds != nil && in.ResetInterval {
		return nil, fmt.Errorf("%w: set interval_seconds or reset it, not both", ErrInvalidWatcherSettings)
	}
	cfg := u.deps.Watcher
	interval := in.IntervalSeconds
	if in.ResetInterval {
		d := int32(defaultProjectWatcherInterval / time.Second)
		interval = &d
	}
	if interval != nil {
		d := time.Duration(*interval) * time.Second
		if d < cfg.minProjectInterval() || d > maxProjectWatcherInterval {
			return nil, fmt.Errorf("%w: interval_seconds must be between %d and %d",
				ErrInvalidWatcherSettings,
				int64(cfg.minProjectInterval()/time.Second), int64(maxProjectWatcherInterval/time.Second))
		}
	}

	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrProjectAccessDenied
		}
		return nil, fmt.Errorf("lookup project: %w", err)
	}
	if err := u.requireProjectAdmin(ctx, project.ID); err != nil {
		return nil, err
	}
	updated, err := u.deps.Stores.Watcher.UpdateProjectConfig(ctx, project.ID, in.Enabled, interval)
	if err != nil {
		return nil, fmt.Errorf("update project watcher config: %w", err)
	}
	slog.Info("project watcher settings updated", "project", projectSlug,
		"enabled", updated.CveWatcherEnabled, "interval_seconds", updated.CveWatcherIntervalSecs)
	return u.projectWatcherResponse(ctx, updated, now())
}
