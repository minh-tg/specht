// This file holds everything the human-alert channel needs and nothing more:
// a payload builder that maps watcher findings (Decision) to the Slack
// message shape {text, attachments:[{title, cve, package, project, severity,
// link}]}, an HMAC-SHA256 signed HTTP POST, and a bounded retry loop.
//
// The channel is DISABLED BY DEFAULT: NewSlackNotifier with an empty webhook
// URL returns a no-op sender, so an unconfigured deployment pays nothing and
// the daemon keeps polling. Failures never propagate — after retries are
// exhausted the notifier logs and returns nil, so a dead webhook can never
// block or fail a poll.
package watcher

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/minh-tg/specht/internal/netutil"
)

// WATCHER_* environment variables for the notification channel. Env sourcing
// happens at wiring time; this package only declares the names and consumes
// what the constructor is given.
const (
	// EnvSlackURL is the single Slack incoming-webhook URL
	// (WATCHER_SLACK_URL). Empty = channel disabled.
	EnvSlackURL = "WATCHER_SLACK_URL"
	// EnvSlackSigningSecret is the HMAC-SHA256 signing key
	// (WATCHER_SLACK_SIGNING_SECRET). Empty = no signature header sent.
	EnvSlackSigningSecret = "WATCHER_SLACK_SIGNING_SECRET"
)

// SlackSignatureHeader carries the HMAC-SHA256 digest of the raw request
// body. Format: hex lowercase of HMAC-SHA256(body) keyed with the signing
// secret, prefixed "sha256=".
const SlackSignatureHeader = "X-Specht-Signature"

const (
	// notifierMaxAttempts is the total number of POST attempts including the
	// first.
	notifierMaxAttempts = 3
	// notifierBaseBackoff is the sleep before the second attempt; it doubles
	// per subsequent retry (500ms, 1s, 2s).
	notifierBaseBackoff = 500 * time.Millisecond
)

// Notification is one finding's Slack attachment row. The daemon wiring
// builds these from a page of created Decisions (NotificationFromDecision)
// and hands the batch to Notify.
type Notification struct {
	// Title is the finding title (advisory summary).
	Title string
	// CVE is the primary vulnerability id (CVE-, GHSA-, or OSV- prefixed).
	CVE string
	// Package is the affected package (name-level purl when available).
	Package string
	// Project is the project display name; ProjectID alone is not enough
	// for humans, so the caller resolves the name.
	Project string
	// Severity is the finding severity (critical/high/medium/low/unknown).
	Severity string
	// Link is the first advisory reference URL, empty when the advisory
	// carries no references.
	Link string
}

// Notifier is the surface the daemon wiring can inject. It is deliberately
// tiny: one batched send, failures logged not returned.
type Notifier interface {
	// Notify sends one Slack message carrying every notification. It never
	// blocks the caller for longer than the retry loop, and it NEVER
	// returns an error: delivery failures are logged and swallowed so a
	// broken webhook cannot fail or stall a poll.
	Notify(ctx context.Context, notifications []Notification) error
}

// SlackNotifier posts Notification batches to a Slack webhook URL with
// HMAC-SHA256 signing and bounded retries.
type SlackNotifier struct {
	webhookURL string
	secret     string
	logger     *slog.Logger
	client     *http.Client
	// sleeper is the wait between attempts. Injectable for deterministic
	// tests; defaults to a cancellable sleep that honors ctx.
	sleeper func(ctx context.Context, d time.Duration) error
}

// NewSlackNotifier builds the notifier. A webhookURL of "" yields a no-op
// sender (Notify returns nil without touching the network), which is the
// default state of an unconfigured deployment. Pass a non-nil logger;
// a nil logger falls back to slog.Default().
func NewSlackNotifier(webhookURL, secret string, logger *slog.Logger) *SlackNotifier {
	if logger == nil {
		logger = slog.Default()
	}
	// A short timeout keeps one dead webhook from tying up a poll thread;
	// the retry budget bounds the total stall.
	return &SlackNotifier{
		webhookURL: webhookURL,
		secret:     secret,
		logger:     logger,
		client:     netutil.SafeHTTPClientForURL(webhookURL, 10*time.Second),
		sleeper:    notifierSleep,
	}
}

// Notify implements Notifier. Empty webhook URL or an empty batch is a
// no-op. The payload is signed, then POSTed up to notifierMaxAttempts times:
// 2xx stops the loop, anything else (non-2xx or a transport error) backs off
// and retries. Exhausted attempts are logged and swallowed (nil returned) —
// silent failure by design, never a poll-blocking error.
func (n *SlackNotifier) Notify(ctx context.Context, notifications []Notification) error {
	if n.webhookURL == "" {
		n.logger.Debug("slack notification skipped: no webhook URL configured")
		return nil
	}
	if len(notifications) == 0 {
		n.logger.Debug("slack notification skipped: empty batch")
		return nil
	}

	body, err := BuildSlackPayload(notifications)
	if err != nil {
		// Un-marshalable values are a programming error, not a transient
		// condition; retrying cannot fix them. Log and move on.
		n.logger.Error("slack payload build failed", "error", err, "count", len(notifications))
		return nil
	}

	postNotifications(ctx, postRequest{
		logger: n.logger, client: n.client, sleeper: n.sleeper,
		channel: "slack", webhookURL: n.webhookURL, secret: n.secret,
	}, body, len(notifications))
	return nil
}

// BuildSlackPayload renders the batch as the Slack message envelope:
//
//	{ "text": "...", "attachments": [ {title, cve, package, project,
//	severity, link}, ... ] }
//
// Field mapping from Notification (whose source is Decision.Finding via
// NotificationFromDecision):
//
//	text       "CVE watcher: N new finding(s)"  (human summary line)
//	title      finding.Title                    (advisory summary)
//	cve        primary vulnerability id         (dimension cve_id)
//	package    affected package                 (display package_name)
//	project    project display name             (resolved by caller)
//	severity   finding.Severity                 (critical..unknown)
//	link       first advisory reference URL     (metadata references[0])
func BuildSlackPayload(notifications []Notification) ([]byte, error) {
	payload := slackPayload{
		Text:        fmt.Sprintf("CVE watcher: %d new finding(s)", len(notifications)),
		Attachments: make([]slackAttachment, 0, len(notifications)),
	}
	for _, n := range notifications {
		payload.Attachments = append(payload.Attachments, slackAttachment(n))
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal slack payload: %w", err)
	}
	return b, nil
}

// slackPayload is the wire form of the envelope; field names are the exact
// JSON keys the Slack API expects.
type slackPayload struct {
	Text        string            `json:"text"`
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Title    string `json:"title"`
	CVE      string `json:"cve"`
	Package  string `json:"package"`
	Project  string `json:"project"`
	Severity string `json:"severity"`
	Link     string `json:"link"`
}

// SignSlackBody computes the X-Specht-Signature value for a raw body:
// "sha256=" + lowercase hex HMAC-SHA256(body) keyed with the secret.
// Exported so the wiring can verify as well as sign; hmac.Equal is
// constant-time, which is the comparison any verifier must use.
func SignSlackBody(body []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// NotificationFromDecision maps one created Decision to a Notification.
// Project is passed in because a Decision carries only the project UUID; the
// caller (daemon wiring) resolves the display name. The mapping is defensive:
// it walks dimensions and display/metadata maps so hand-built fixtures and
// parser variants both degrade gracefully, and it never panics on nil maps.
//
//   - title    ← Finding.Title (advisory summary; never empty for Created)
//   - cve      ← dimension key "vulnerability_id" (primary id), fallback
//     metadata["advisory_id"]
//   - package  ← display["package_name"] (name-level purl), fallback
//     dimension key "purl" (versioned), fallback display["purl"]
//   - severity ← Finding.Severity
//   - link     ← first entry of metadata["references"], fallback "" if the
//     advisory carries no references
func NotificationFromDecision(d Decision, project string) Notification {
	fp := d.Finding
	n := Notification{
		Title:    fp.Title,
		Project:  project,
		Severity: fp.Severity,
		Package:  mapString(fp.Display, "package_name"),
	}

	for _, dim := range fp.Dimensions {
		switch dim.Key {
		case "vulnerability_id":
			if n.CVE == "" {
				n.CVE = dim.Value
			}
		case "purl":
			if n.Package == "" {
				n.Package = dim.Value
			}
		}
	}
	if n.CVE == "" {
		n.CVE = mapString(fp.Metadata, "advisory_id")
	}
	if n.Package == "" {
		n.Package = mapString(fp.Display, "purl")
	}

	if refs, ok := stringSlice(fp.Metadata, "references"); ok && len(refs) > 0 {
		n.Link = refs[0]
	} else if refs, ok := stringSlice(fp.Display, "references"); ok && len(refs) > 0 {
		n.Link = refs[0]
	}
	return n
}

// mapString extracts a string value from a JSON-ish map used by
// FindingPayload.Display/Metadata, tolerating absent keys and non-string
// values.
func mapString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return s
}

// stringSlice extracts a []any-of-strings value (the shape json.Unmarshal
// produces for JSON arrays) from a JSON-ish map.
func stringSlice(m map[string]any, key string) ([]string, bool) {
	if m == nil {
		return nil, false
	}
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	list, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out, true
}

// notifierSleep waits d or returns ctx.Err() when the context is done first
// (mirrors daemon.defaultSleep).
func notifierSleep(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
