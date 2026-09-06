package tracker

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// WebHookTracker is a Tracker adapter that fans finding lifecycle events out
// to one or more HTTP webhook endpoints. Each Event is POSTed as a JSON
// payload; failures are logged and swallowed (best-effort), so a dead or slow
// webhook can never stall ingest or verification.
//
// webhook fan-out for finding lifecycle events.
type WebHookTracker struct {
	endpoints []string
	client    *http.Client
	logger    func(string, ...any)
}

// WebHookTrackerConfig holds the endpoint list and HTTP client tuning.
type WebHookTrackerConfig struct {
	Endpoints []string
	Timeout   time.Duration
}

// NewWebHookTracker builds a WebHookTracker from the given config. An empty
// endpoint list yields a tracker that no-ops (safe default).
func NewWebHookTracker(cfg WebHookTrackerConfig, logger func(string, ...any)) *WebHookTracker {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	return &WebHookTracker{
		endpoints: cfg.Endpoints,
		client:    &http.Client{Timeout: cfg.Timeout},
		logger:    logger,
	}
}

// Name returns the provider name for logging and dispatch.
func (t *WebHookTracker) Name() string { return "webhook" }

// CreateIssue fans out an EventCreated event to all configured webhooks.
// Since webhooks are push-only (no issue ID returned), this returns a
// deterministic synthetic ID derived from the finding fingerprint. When no
// endpoints are configured, it returns an empty ID (no-op).
func (t *WebHookTracker) CreateIssue(ctx context.Context, event Event) (IssueID, error) {
	if len(t.endpoints) == 0 {
		return "", nil
	}
	t.dispatch(ctx, event)
	return IssueID(event.Fingerprint), nil
}

// UpdateIssue fans out an event update to all configured webhooks.
func (t *WebHookTracker) UpdateIssue(ctx context.Context, issueID IssueID, event Event) error {
	t.dispatch(ctx, event)
	return nil
}

// dispatch POSTs the event payload to every configured webhook endpoint.
func (t *WebHookTracker) dispatch(ctx context.Context, event Event) {
	if len(t.endpoints) == 0 {
		return
	}
	payload, err := json.Marshal(event)
	if err != nil {
		if t.logger != nil {
			t.logger("webhook marshal failed", "error", err)
		}
		return
	}

	for _, url := range t.endpoints {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
		if err != nil {
			if t.logger != nil {
				t.logger("webhook request build failed", "url", url, "error", err)
			}
			continue
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Tracker-Event", event.Type)

		resp, err := t.client.Do(req)
		if err != nil {
			if t.logger != nil {
				t.logger("webhook dispatch failed", "url", url, "error", err)
			}
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if t.logger != nil {
			t.logger("webhook dispatched", "url", url, "event", event.Type, "status", resp.StatusCode)
		}
	}
}

// EnvWebHookURLs parses a comma-separated list of webhook URLs from the
// environment, returning nil if the env var is empty.
func EnvWebHookURLs(envVar string, env func(string) string) []string {
	raw := env(envVar)
	if raw == "" {
		return nil
	}
	var urls []string
	for _, u := range strings.Split(raw, ",") {
		if u = strings.TrimSpace(u); u != "" {
			urls = append(urls, u)
		}
	}
	return urls
}

// Compile-time check that WebHookTracker satisfies the Tracker interface.
var _ Tracker = (*WebHookTracker)(nil)
