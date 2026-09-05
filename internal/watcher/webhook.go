// This file holds the generic webhook channel and the fan-out wrapper:
// a transport-neutral JSON POST of the same Notification batch Slack gets,
// signed with the same HMAC scheme, plus a multi-notifier that delivers to
// every configured channel. Semantics match Slack exactly: disabled by
// default, bounded retries, failures logged and swallowed so a dead endpoint
// can never block or fail a poll.
package watcher

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

const (
	// EnvWebhookURL is the generic webhook endpoint (WATCHER_WEBHOOK_URL).
	// Empty = channel disabled.
	EnvWebhookURL = "WATCHER_WEBHOOK_URL"
	// EnvWebhookSigningSecret is the HMAC-SHA256 signing key
	// (WATCHER_WEBHOOK_SIGNING_SECRET). Empty = no signature header sent.
	EnvWebhookSigningSecret = "WATCHER_WEBHOOK_SIGNING_SECRET"
)

// WebhookEventCreated is the event type of the initial webhook envelope.
// It anticipates the event taxonomy (regressed, gate-blocking,
// …); the first slice only emits creation batches.
const WebhookEventCreated = "findings.created"

// webhookPayload is the wire form: event type plus the 1:1 notification
// rows. Field names are stable API: consumers verify the signature over
// these exact bytes.
type webhookPayload struct {
	Event         string       `json:"event"`
	Notifications []webhookRow `json:"notifications"`
}

type webhookRow struct {
	Title    string `json:"title"`
	CVE      string `json:"cve,omitempty"`
	Package  string `json:"package,omitempty"`
	Project  string `json:"project,omitempty"`
	Severity string `json:"severity,omitempty"`
	Link     string `json:"link,omitempty"`
}

// BuildWebhookPayload renders the batch as the generic webhook envelope.
func BuildWebhookPayload(notifications []Notification) ([]byte, error) {
	rows := make([]webhookRow, len(notifications))
	for i, n := range notifications {
		rows[i] = webhookRow{
			Title: n.Title, CVE: n.CVE, Package: n.Package,
			Project: n.Project, Severity: n.Severity, Link: n.Link,
		}
	}
	return json.Marshal(webhookPayload{Event: WebhookEventCreated, Notifications: rows})
}

// WebhookNotifier posts Notification batches to a generic webhook URL with
// HMAC-SHA256 signing and bounded retries.
type WebhookNotifier struct {
	webhookURL string
	secret     string
	logger     *slog.Logger
	client     *http.Client
	sleeper    func(ctx context.Context, d time.Duration) error
}

// NewWebhookNotifier builds the notifier. A webhookURL of "" yields a
// no-op sender; a nil logger falls back to slog.Default().
func NewWebhookNotifier(webhookURL, secret string, logger *slog.Logger) *WebhookNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	return &WebhookNotifier{
		webhookURL: webhookURL,
		secret:     secret,
		logger:     logger,
		client:     &http.Client{Timeout: 10 * time.Second},
		sleeper:    notifierSleep,
	}
}

// Notify implements Notifier with Slack-identical delivery semantics.
func (n *WebhookNotifier) Notify(ctx context.Context, notifications []Notification) error {
	if n.webhookURL == "" {
		n.logger.Debug("webhook notification skipped: no webhook URL configured")
		return nil
	}
	if len(notifications) == 0 {
		n.logger.Debug("webhook notification skipped: empty batch")
		return nil
	}
	body, err := BuildWebhookPayload(notifications)
	if err != nil {
		n.logger.Error("webhook payload build failed", "error", err, "count", len(notifications))
		return nil
	}
	postNotifications(ctx, n.logger, n.client, n.sleeper, "webhook", n.webhookURL, n.secret, body, len(notifications))
	return nil
}

// FanoutNotifier delivers each batch to every child notifier. Children
// already swallow their own failures, so fan-out preserves the interface
// guarantee: it never returns an error and one dead channel never blocks
// the others.
type FanoutNotifier struct {
	children []Notifier
}

// NewFanoutNotifier builds a fan-out over the given notifiers. Nil and empty
// are both a no-op Notify.
func NewFanoutNotifier(notifiers ...Notifier) *FanoutNotifier {
	return &FanoutNotifier{children: notifiers}
}

// Notify implements Notifier.
func (f *FanoutNotifier) Notify(ctx context.Context, notifications []Notification) error {
	for _, c := range f.children {
		if c == nil {
			continue
		}
		_ = c.Notify(ctx, notifications)
	}
	return nil
}

// postNotifications is the shared delivery loop behind every channel:
// sign, POST up to notifierMaxAttempts times with doubling backoff, log and
// swallow everything. 2xx stops the loop.
func postNotifications(ctx context.Context, logger *slog.Logger, client *http.Client, sleeper func(ctx context.Context, d time.Duration) error, channel, webhookURL, secret string, body []byte, count int) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, webhookURL, bytes.NewReader(body))
	if err != nil {
		logger.Error(channel+" notification request build failed", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if secret != "" {
		req.Header.Set(SlackSignatureHeader, SignSlackBody(body, secret))
	}

	backoff := notifierBaseBackoff
	for attempt := 1; attempt <= notifierMaxAttempts; attempt++ {
		resp, err := client.Do(req)
		switch {
		case err == nil && resp.StatusCode >= 200 && resp.StatusCode < 300:
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			logger.Info(channel+" notification delivered", "attempt", attempt, "count", count)
			return
		case err == nil:
			drain := io.LimitReader(resp.Body, 1024)
			msg, _ := io.ReadAll(drain)
			resp.Body.Close()
			logger.Warn(channel+" notification rejected",
				"attempt", attempt, "status", resp.StatusCode, "body", strings.TrimSpace(string(msg)))
		default:
			logger.Warn(channel+" notification transport error",
				"attempt", attempt, "error", err)
		}
		if attempt < notifierMaxAttempts {
			if err := sleeper(ctx, backoff); err != nil {
				logger.Warn(channel+" notification aborted", "error", err)
				return
			}
			backoff *= 2
		}
	}

	logger.Error(channel+" notification failed after retries",
		"attempts", notifierMaxAttempts, "count", count)
}
