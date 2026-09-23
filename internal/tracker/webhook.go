package tracker

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// WebHookSignatureHeader carries the HMAC-SHA256 digest of the raw request
// body. Format: hex lowercase of HMAC-SHA256(body) keyed with the signing
// secret, prefixed "sha256=" — the same scheme the watcher notifiers use, so
// a receiver can verify tracker and watcher payloads identically.
const WebHookSignatureHeader = "X-Specht-Signature"

// EnvWebHookSecret is the HMAC-SHA256 signing key for tracker webhook
// payloads (WATCHER_WEBHOOK_SIGNING_SECRET, shared with the watcher generic
// webhook so one secret covers both outbound channels). Empty = unsigned.
const EnvWebHookSecret = "WATCHER_WEBHOOK_SIGNING_SECRET"

// WebHookTracker is a Tracker adapter that fans finding lifecycle events out
// to one or more HTTP webhook endpoints. Each Event is POSTed as a JSON
// payload, optionally signed with HMAC-SHA256; failures are logged and
// swallowed (best-effort), so a dead or slow webhook can never stall ingest
// or verification.
//
// webhook fan-out for finding lifecycle events.
type WebHookTracker struct {
	endpoints []string
	secret    string
	client    *http.Client
	logger    func(string, ...any)
}

// WebHookTrackerConfig holds the endpoint list, optional HMAC-SHA256 signing
// secret, and HTTP client tuning. An empty secret sends no signature header.
type WebHookTrackerConfig struct {
	Endpoints []string
	Secret    string
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
		secret:    cfg.Secret,
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
// Delivery is asynchronous and best-effort: the payload is marshalled
// synchronously, then each endpoint is POSTed on its own goroutine with a
// context detached from the caller (context.WithoutCancel), so a slow or
// dead webhook can never stall ingest or verification — even if the caller
// cancels its context before delivery completes. Each POST is still bounded
// by the short client Timeout configured at construction, and failures are
// logged and swallowed.
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

	// Detach from the caller's context: a cancelled parent mid-dispatch must
	// only abort in-flight POSTs, never this return (mirrors the watcher
	// daemon's notifyCreated). Endpoints are POSTed concurrently so N dead
	// endpoints cost one timeout, not N sequential ones.
	deliveryCtx := context.WithoutCancel(ctx)
	for _, url := range t.endpoints {
		go t.post(deliveryCtx, url, event.Type, payload)
	}
}

// post sends one signed JSON payload to a single webhook endpoint and logs
// the outcome. It runs on a background goroutine; errors are logged and
// swallowed (best-effort delivery by design).
func (t *WebHookTracker) post(ctx context.Context, url, eventType string, payload []byte) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		if t.logger != nil {
			t.logger("webhook request build failed", "url", url, "error", err)
		}
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tracker-Event", eventType)
	if t.secret != "" {
		req.Header.Set(WebHookSignatureHeader, signWebHookBody(payload, t.secret))
	}

	resp, err := t.client.Do(req)
	if err != nil {
		if t.logger != nil {
			t.logger("webhook dispatch failed", "url", url, "error", err)
		}
		return
	}
	// Draining and closing are best-effort; the HTTP status is the delivery result.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if t.logger != nil {
		t.logger("webhook dispatched", "url", url, "event", eventType, "status", resp.StatusCode)
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

// signWebHookBody computes the X-Specht-Signature value for a raw payload:
// "sha256=" + lowercase hex HMAC-SHA256(body) keyed with the secret. It
// mirrors watcher.SignSlackBody so one verification path covers both
// signers; hmac.Equal is the constant-time comparison a verifier must use.
func signWebHookBody(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Compile-time check that WebHookTracker satisfies the Tracker interface.
var _ Tracker = (*WebHookTracker)(nil)
