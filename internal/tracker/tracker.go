// Package tracker defines the core seam for creating and transitioning
// external tracking-system issues (Jira, Linear, GitHub Issues, …) from
// Specht findings. It follows the one-core-plus-plugins philosophy: the core
// owns the lifecycle semantics and the event taxonomy; the provider-specific
// transport sits behind the Tracker interface and is wired at compile time.
//
// tracker/messaging integrations.
package tracker

import (
	"context"
	"log/slog"
	"os"
	"time"
)

// Event is the canonical lifecycle event the tracker reacts to. It mirrors
// the persisted finding_events.event_type vocabulary (enforced by DB CHECK)
// plus a synthetic "created" event for the initial finding observation.
type Event struct {
	// Type is the event taxonomy. Mirrors finding_events.event_type for
	// persisted events; "created" is the synthetic initial-observation event.
	Type string
	// FindingID is the Specht finding UUID.
	FindingID string
	// ProjectSlug is the human-readable project identifier for routing.
	ProjectSlug string
	// Severity is the finding severity string (critical/high/medium/low).
	Severity string
	// SeverityRank is the numeric severity rank the gate uses.
	SeverityRank int16
	// Title is the finding's current advisory summary.
	Title string
	// Fingerprint uniquely identifies the finding within a project + kind.
	Fingerprint string
	// FindingKind is the scanner dimension (sca, sast, iac, secret, dast, …).
	FindingKind string
	// OccurredAt is when the event was observed.
	OccurredAt time.Time
	// Changes carries event-specific payload (report_id, previous_state,
	// new_state, …) for events that have one.
	Changes map[string]any
}

// IssueID identifies an external issue created by a tracker provider.
type IssueID string

// Tracker is the core seam: a provider adapter that creates or transitions
// an external issue in response to a finding lifecycle event. Implementations
// are compile-time wired and env-disabled by default.
type Tracker interface {
	// CreateIssue creates an external issue for a finding lifecycle event.
	// Returns the provider issue ID and nil on success. A non-nil error
	// aborts the dispatch for this event; the caller logs and continues.
	CreateIssue(ctx context.Context, event Event) (IssueID, error)
	// UpdateIssue transitions an existing external issue (e.g. when a
	// finding is verified fixed or regressed). issueID was returned by a
	// prior CreateIssue. A no-op implementation need not implement this.
	UpdateIssue(ctx context.Context, issueID IssueID, event Event) error
	// Name returns the provider name for logging.
	Name() string
}

// NoopTracker is a Tracker that does nothing. It is the default when no
// provider is configured.
type NoopTracker struct{}

func (NoopTracker) CreateIssue(ctx context.Context, event Event) (IssueID, error) {
	return "", nil
}

func (NoopTracker) UpdateIssue(ctx context.Context, issueID IssueID, event Event) error {
	return nil
}
func (NoopTracker) Name() string { return "noop" }

// EventType constants mirror the finding_events.vocabulary and the
// synthetic creation event.
const (
	EventCreated          = "created"
	EventVerifiedFixed    = "verified_fixed"
	EventRegression       = "regression"
	EventReopenedSeverity = "reopened_severity_change"
)

// EnvTrackerProvider selects the tracker provider ("noop" by default).
const EnvTrackerProvider = "TRACKER_PROVIDER"

// EnvTrackerBaseURL is the provider API base URL for HTTP-based trackers.
const EnvTrackerBaseURL = "TRACKER_BASE_URL"

// EnvTrackerProjectID maps Specht projects to a provider project/queue.
const EnvTrackerProjectID = "TRACKER_PROJECT_ID"

// EnvTrackerToken is the provider API token (bearer auth).
const EnvTrackerToken = "TRACKER_API_TOKEN"

// Config holds the resolved tracker configuration.
type Config struct {
	Provider    string
	BaseURL     string
	ProjectID   string
	APIToken    string
	ProjectSlug string
}

// ResolveConfig reads tracker env vars into a Config.
func ResolveConfig() Config {
	return Config{
		Provider:  envOrDefault(EnvTrackerProvider, "noop"),
		BaseURL:   getenv(EnvTrackerBaseURL),
		ProjectID: getenv(EnvTrackerProjectID),
		APIToken:  getenv(EnvTrackerToken),
	}
}

// EnvEnabled reports whether a non-noop tracker is configured.
func EnvEnabled() bool {
	return ResolveConfig().Provider != "noop" && ResolveConfig().Provider != ""
}

// Dispatcher subscribes to finding lifecycle events and dispatches each to
// the configured Tracker. It is the bridge between Specht's event log and
// the external tracking system.
type Dispatcher struct {
	tracker Tracker
	logger  *slog.Logger
}

// NewDispatcher builds a dispatcher over a tracker. A nil tracker yields a
// no-op dispatcher.
func NewDispatcher(tracker Tracker, logger *slog.Logger) *Dispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	if tracker == nil {
		tracker = NoopTracker{}
	}
	return &Dispatcher{tracker: tracker, logger: logger}
}

// Dispatch sends a finding lifecycle event to the tracker. It is
// best-effort: delivery failures are logged and swallowed.
//
// Dispatch does not serialize tracker calls behind a mutex: HTTP-backed
// trackers (webhook) dispatch asynchronously so their network I/O never
// blocks the request path, and stateful in-process trackers own their own
// locking. A slow delivery must not queue unrelated events behind it.
func (d *Dispatcher) Dispatch(ctx context.Context, event Event) {
	switch event.Type {
	case EventVerifiedFixed, EventRegression, EventReopenedSeverity:
		issueID, _ := event.Changes["external_id"].(string)
		if err := d.tracker.UpdateIssue(ctx, IssueID(issueID), event); err != nil {
			d.logger.Warn("tracker update failed", "provider", d.tracker.Name(),
				"finding", event.FindingID, "event", event.Type, "error", err)
		}
	case EventCreated:
		id, err := d.tracker.CreateIssue(ctx, event)
		if err != nil {
			d.logger.Warn("tracker create failed", "provider", d.tracker.Name(),
				"finding", event.FindingID, "event", event.Type, "error", err)
			return
		}
		if id != "" {
			d.logger.Info("tracker issue created", "provider", d.tracker.Name(),
				"finding", event.FindingID, "issue_id", string(id))
		}
	default:
		d.logger.Debug("tracker ignoring event", "type", event.Type, "finding", event.FindingID)
	}
}

func envOrDefault(key, def string) string {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	return v
}

func getenv(key string) string {
	return os.Getenv(key)
}
