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
	"sync"
	"sync/atomic"
	"time"

	"github.com/minh-tg/specht/internal/netutil"
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
type WebHookTracker struct {
	endpoints  []string
	secret     string
	client     *http.Client
	logger     func(string, ...any)
	jobs       chan webhookJob
	queueDepth atomic.Int64
	mu         sync.RWMutex
	closed     bool
	ctx        context.Context
	cancel     context.CancelFunc
	workers    sync.WaitGroup
}

type webhookJob struct {
	ctx       context.Context
	url       string
	eventType string
	payload   []byte
}

const (
	webhookWorkers = 8
	webhookQueue   = 256
)

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
	ctx, cancel := context.WithCancel(context.Background())
	t := &WebHookTracker{
		ctx: ctx, cancel: cancel,
		endpoints: cfg.Endpoints,
		secret:    cfg.Secret,
		client:    netutil.NewSafeHTTPClient(cfg.Timeout),
		logger:    logger,
		jobs:      make(chan webhookJob, webhookQueue),
	}
	if len(t.endpoints) > 0 {
		for i := 0; i < webhookWorkers; i++ {
			t.workers.Go(t.worker)
		}
	}
	return t
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
// cancels its context before delivery completes. A fixed worker pool and
// bounded queue cap resource usage; excess deliveries are dropped. Each POST
// is still bounded by the short client Timeout configured at construction,
// and failures are logged and swallowed.
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
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.closed {
		return
	}
	for _, url := range t.endpoints {
		job := webhookJob{ctx: deliveryCtx, url: url, eventType: event.Type, payload: payload}
		t.queueDepth.Add(1)
		select {
		case t.jobs <- job:
		default:
			t.queueDepth.Add(-1)
			if t.logger != nil {
				t.logger("webhook queue full; delivery dropped", "target", netutil.RedactURL(url))
			}
		}
	}
}

func (t *WebHookTracker) worker() {
	for {
		if t.ctx.Err() != nil {
			return
		}
		select {
		case <-t.ctx.Done():
			return
		case job, ok := <-t.jobs:
			if !ok {
				return
			}
			t.queueDepth.Add(-1)
			t.deliver(job)
		}
	}
}

func (t *WebHookTracker) deliver(job webhookJob) {
	ctx, cancel := context.WithCancel(job.ctx)
	stop := context.AfterFunc(t.ctx, cancel)
	defer stop()
	defer cancel()
	t.post(ctx, job.url, job.eventType, job.payload)
}

// Close cancels best-effort deliveries, stops workers and drops queued jobs.
// It is safe to call more than once or alongside dispatch.
func (t *WebHookTracker) Close() error {
	t.mu.Lock()
	if !t.closed {
		t.closed = true
		t.cancel()
		close(t.jobs)
	}
	t.mu.Unlock()
	t.workers.Wait()
	for range t.jobs {
		t.queueDepth.Add(-1)
	}
	t.client.CloseIdleConnections()
	return nil
}

// QueueDepth reports the number of queued or active deliveries.
func (t *WebHookTracker) QueueDepth() int {
	return int(t.queueDepth.Load())
}

// post sends one signed JSON payload to a single webhook endpoint and logs
// the outcome. It runs on a background goroutine; errors are logged and
// swallowed (best-effort delivery by design).
func (t *WebHookTracker) post(ctx context.Context, url, eventType string, payload []byte) {
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(payload))
	if err != nil {
		if t.logger != nil {
			t.logger("webhook request build failed", "target", netutil.RedactURL(url), "error", netutil.StripURLError(err))
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
			t.logger("webhook dispatch failed", "target", netutil.RedactURL(url), "error", netutil.StripURLError(err))
		}
		return
	}
	// Draining and closing are best-effort; the HTTP status is the delivery result.
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if t.logger != nil {
		t.logger("webhook dispatched", "target", netutil.RedactURL(url), "event", eventType, "status", resp.StatusCode)
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
