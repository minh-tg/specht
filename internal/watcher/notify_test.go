// ***REMOVED***: the Slack notification envelope. All checks are offline and
// deterministic — the receiver is an httptest server, the clock/retry sleeper
// is injected, and there is no network or external HTTP SDK involvement.
package watcher

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xMinhx/specht/internal/scanner"
)

// testNotification builds a representative Notification for envelope tests.
func testNotification() Notification {
	return Notification{
		Title:    "Prototype pollution in lodash",
		CVE:      "CVE-2019-10744",
		Package:  "pkg:npm/lodash",
		Project:  "acme-web",
		Severity: "high",
		Link:     "https://osv.dev/vulnerability/CVE-2019-10744",
	}
}

// newTestLogger captures slog output into a buffer for assertions.
func newTestLogger() (*slog.Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	return logger, &buf
}

func TestBuildSlackPayload_Shape(t *testing.T) {
	in := []Notification{
		testNotification(),
		{Title: "Empty fields still serialize", CVE: "", Package: "", Project: "", Severity: "", Link: ""},
	}
	raw, err := BuildSlackPayload(in)
	if err != nil {
		t.Fatalf("BuildSlackPayload error: %v", err)
	}

	// The exact wire form (brief keys, no extras) assertions on the raw
	// map make a structurally-over-marshalled payload fail loudly.
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if got["text"] != "CVE watcher: 2 new finding(s)" {
		t.Errorf("text = %q, want %q", got["text"], "CVE watcher: 2 new finding(s)")
	}
	atts, ok := got["attachments"].([]any)
	if !ok || len(atts) != 2 {
		t.Fatalf("attachments = %#v, want 2 entries", got["attachments"])
	}
	first, ok := atts[0].(map[string]any)
	if !ok {
		t.Fatalf("attachment[0] = %#v, want object", atts[0])
	}
	want := map[string]string{
		"title":    "Prototype pollution in lodash",
		"cve":      "CVE-2019-10744",
		"package":  "pkg:npm/lodash",
		"project":  "acme-web",
		"severity": "high",
		"link":     "https://osv.dev/vulnerability/CVE-2019-10744",
	}
	for key, val := range want {
		if first[key] != val {
			t.Errorf("attachment.%s = %v, want %q", key, first[key], val)
		}
	}
	for key := range first {
		if _, ok := want[key]; !ok {
			t.Errorf("unexpected attachment key %q", key)
		}
	}
}

func TestBuildSlackPayload_EmptyBatch(t *testing.T) {
	raw, err := BuildSlackPayload(nil)
	if err != nil {
		t.Fatalf("BuildSlackPayload(nil) error: %v", err)
	}
	if !strings.Contains(string(raw), `"attachments":[]`) {
		t.Errorf("empty batch payload = %s, want empty attachments array", raw)
	}
	if !strings.Contains(string(raw), "0 new finding(s)") {
		t.Errorf("empty batch text = %s, want 0 count", raw)
	}
}

func TestSignSlackBody_HMAC(t *testing.T) {
	const secret = "sekret"
	body := []byte(`{"text":"hello"}`)
	got := SignSlackBody(body, secret)
	if !strings.HasPrefix(got, "sha256=") {
		t.Fatalf("signature %q lacks sha256= prefix", got)
	}

	// Recompute the canonical HMAC-SHA256 in the test and compare with
	// the constant-time hmac.Equal — the comparison a verifier must use.
	wantMac := hmac.New(sha256.New, []byte(secret))
	wantMac.Write(body)
	want := "sha256=" + hex.EncodeToString(wantMac.Sum(nil))
	if !hmac.Equal([]byte(got), []byte(want)) {
		t.Errorf("signature = %q, want %q", got, want)
	}

	// A different body (or key) must not verify — guards against signing a
	// stale byte sequence.
	other := SignSlackBody([]byte(`{"text":"nope"}`), secret)
	if hmac.Equal([]byte(other), []byte(want)) {
		t.Error("signature did not change with body — HMAC likely not bound to body")
	}
}

// recordSleeper returns a sleeper that records each requested delay and
// returns immediately (deterministic; no real waiting).
func recordSleeper(rec *[]time.Duration) func(context.Context, time.Duration) error {
	return func(_ context.Context, d time.Duration) error {
		*rec = append(*rec, d)
		return nil
	}
}

func TestNotify_RetriesThenSuccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	logger, _ := newTestLogger()
	n := NewSlackNotifier(srv.URL, "sekret", logger)
	var sleeps []time.Duration
	n.sleeper = recordSleeper(&sleeps)

	if err := n.Notify(context.Background(), []Notification{testNotification()}); err != nil {
		t.Fatalf("Notify returned error: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("server calls = %d, want 3 (2 failures then success)", got)
	}
	wantSleeps := []time.Duration{500 * time.Millisecond, 1 * time.Second}
	if len(sleeps) != len(wantSleeps) {
		t.Fatalf("sleeps = %v, want %v", sleeps, wantSleeps)
	}
	for i := range wantSleeps {
		if sleeps[i] != wantSleeps[i] {
			t.Errorf("sleep[%d] = %v, want %v", i, sleeps[i], wantSleeps[i])
		}
	}
}

func TestNotify_RetriesExhaustedSilentFailure(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusBadGateway) // 502 every time
	}))
	defer srv.Close()

	logger, buf := newTestLogger()
	n := NewSlackNotifier(srv.URL, "sekret", logger)
	var sleeps []time.Duration
	n.sleeper = recordSleeper(&sleeps)

	// Silent failure: nil returned, error only logged.
	if err := n.Notify(context.Background(), []Notification{testNotification()}); err != nil {
		t.Fatalf("Notify returned error on exhausted retries: %v", err)
	}
	if got := calls.Load(); got != 3 {
		t.Errorf("server calls = %d, want 3", got)
	}
	if len(sleeps) != 2 {
		t.Errorf("sleeps = %v, want 2", sleeps)
	}
	if !strings.Contains(buf.String(), "failed after retries") {
		t.Errorf("expected 'failed after retries' in log, got: %s", buf.String())
	}
}

func TestNotify_TransportErrorRetried(t *testing.T) {
	// Server closes connections without responding → transport errors.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			t.Fatal("server does not support hijacking")
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		conn.Close()
	}))
	defer srv.Close()

	logger, buf := newTestLogger()
	n := NewSlackNotifier(srv.URL, "sekret", logger)
	var sleeps []time.Duration
	n.sleeper = recordSleeper(&sleeps)

	if err := n.Notify(context.Background(), []Notification{testNotification()}); err != nil {
		t.Fatalf("Notify returned error on transport failures: %v", err)
	}
	if len(sleeps) != 2 {
		t.Errorf("sleeps = %v, want 2 (each transport error backed off)", sleeps)
	}
	if !strings.Contains(buf.String(), "failed after retries") {
		t.Errorf("expected 'failed after retries' in log, got: %s", buf.String())
	}
}

func TestNotify_2xxStopsImmediately(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusAccepted) // 202 still counts as success
	}))
	defer srv.Close()

	logger, _ := newTestLogger()
	n := NewSlackNotifier(srv.URL, "", logger) // no secret → no signature header
	var sleeps []time.Duration
	n.sleeper = recordSleeper(&sleeps)

	if err := n.Notify(context.Background(), []Notification{testNotification()}); err != nil {
		t.Fatalf("Notify error: %v", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("server calls = %d, want 1", got)
	}
	if len(sleeps) != 0 {
		t.Errorf("sleeps = %v, want none on first-attempt success", sleeps)
	}
}

func TestNotify_NoOpWhenURLUnconfigured(t *testing.T) {
	logger, _ := newTestLogger()
	n := NewSlackNotifier("", "sekret", logger)
	// No HTTP server configured: an attempted send would fail loudly; a
	// correct no-op never touches the network.
	if err := n.Notify(context.Background(), []Notification{testNotification()}); err != nil {
		t.Fatalf("Notify on unconfigured notifier returned error: %v", err)
	}
	if err := n.Notify(context.Background(), nil); err != nil {
		t.Fatalf("Notify(nil) returned error: %v", err)
	}
}

func TestNotify_EmptyBatchNoOp(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewSlackNotifier(srv.URL, "sekret", nil)
	if err := n.Notify(context.Background(), nil); err != nil {
		t.Fatalf("Notify(nil) error: %v", err)
	}
	if got := calls.Load(); got != 0 {
		t.Errorf("server calls = %d, want 0 (empty batch never posted)", got)
	}
}

func TestNotify_SignatureHeader(t *testing.T) {
	const secret = "shared-secret"
	var gotBody []byte
	var gotHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(SlackSignatureHeader)
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewSlackNotifier(srv.URL, secret, nil)
	if err := n.Notify(context.Background(), []Notification{testNotification()}); err != nil {
		t.Fatalf("Notify error: %v", err)
	}
	if gotHeader == "" {
		t.Fatal("signature header not sent")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(gotHeader), []byte(want)) {
		t.Errorf("X-Specht-Signature = %q, want %q", gotHeader, want)
	}
}

func TestNotify_ContextCancelledMidRetry(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	logger, buf := newTestLogger()
	n := NewSlackNotifier(srv.URL, "sekret", logger)
	// Sleeper honours ctx and returns ctx.Err().
	n.sleeper = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled: first retry aborts
	if err := n.Notify(ctx, []Notification{testNotification()}); err != nil {
		t.Fatalf("Notify on cancelled ctx returned error (should be silent): %v", err)
	}
	if !strings.Contains(buf.String(), "aborted") {
		t.Errorf("expected 'aborted' in log, got: %s", buf.String())
	}
}

// sampleFindings returns a Created decision with representative Dimensions /
// Display / Metadata maps to exercise NotificationFromDecision's mapping.
func sampleFindings() Decision {
	return Decision{
		Created: true,
		Finding: FindingPayload{
			ProjectID:   "11111111-1111-1111-1111-111111111111",
			FindingKind: FindingKindCVEWatcher,
			Title:       "Prototype pollution in lodash",
			Severity:    "high",
			Dimensions: []scanner.Dimension{
				{Key: "purl", Value: "pkg:npm/lodash@4.17.19"},
				{Key: "severity", Value: "high"},
				{Key: "cve_id", Value: "CVE-2019-10744"},
				{Key: "component.identity", Value: "pkg:npm/lodash"},
				{Key: "source", Value: DimensionSourceValue},
			},
			Display: map[string]any{
				"package_name": "pkg:npm/lodash",
				"severity":     "high",
				"purl":         "pkg:npm/lodash@4.17.19",
			},
			Metadata: map[string]any{
				"advisory_id": "GHSA-jq35-85cj-fj4p",
				"references":  []any{"https://github.com/advisories/GHSA-jq35-85cj-fj4p", "https://nvd.nist.gov/vuln/detail/CVE-2019-10744"},
			},
		},
	}
}

func TestNotificationFromDecision_Mapping(t *testing.T) {
	n := NotificationFromDecision(sampleFindings(), "acme-web")
	want := Notification{
		Title:    "Prototype pollution in lodash",
		CVE:      "CVE-2019-10744",
		Package:  "pkg:npm/lodash",
		Project:  "acme-web",
		Severity: "high",
		Link:     "https://github.com/advisories/GHSA-jq35-85cj-fj4p",
	}
	if n != want {
		t.Errorf("NotificationFromDecision = %+v, want %+v", n, want)
	}
}

func TestNotificationFromDecision_Fallbacks(t *testing.T) {
	// Missing cve_id dimension and package_name display; degraded inputs
	// must fall back without panicking.
	d := sampleFindings()
	d.Finding.Dimensions = []scanner.Dimension{{Key: "source", Value: DimensionSourceValue}}
	d.Finding.Display = nil // severely degraded
	n := NotificationFromDecision(d, "acme")
	if n.CVE != "GHSA-jq35-85cj-fj4p" {
		t.Errorf("CVE fallback = %q, want advisory_id GHSA-jq35-85cj-fj4p", n.CVE)
	}
	if n.Package != "" {
		t.Errorf("Package = %q, want empty when nothing available", n.Package)
	}
	if n.Link != "https://github.com/advisories/GHSA-jq35-85cj-fj4p" {
		t.Errorf("Link = %q, want first reference", n.Link)
	}
}

func TestNotificationFromDecision_NoReferences(t *testing.T) {
	d := sampleFindings()
	d.Finding.Metadata = map[string]any{"advisory_id": "OSV-2026-0001"}
	n := NotificationFromDecision(d, "acme")
	if n.Link != "" {
		t.Errorf("Link = %q, want empty with no references", n.Link)
	}
	if n.CVE != "CVE-2019-10744" {
		t.Errorf("CVE = %q, want cve_id dimension", n.CVE)
	}
}

// TestEnvelopeFlowEndToEnd asserts the full path: a Decision → notification
// → signed HTTP POST → receiver decodes the exact brief envelope.
func TestEnvelopeFlowEndToEnd(t *testing.T) {
	const secret = "s3cret"
	var gotHeader string
	var gotPayload []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get(SlackSignatureHeader)
		gotPayload, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	d := sampleFindings()
	notif := NotificationFromDecision(d, "acme-web")
	n := NewSlackNotifier(srv.URL, secret, nil)
	if err := n.Notify(context.Background(), []Notification{notif}); err != nil {
		t.Fatalf("Notify error: %v", err)
	}

	var payload slackPayload
	if err := json.Unmarshal(gotPayload, &payload); err != nil {
		t.Fatalf("unmarshal delivered payload: %v", err)
	}
	if len(payload.Attachments) != 1 {
		t.Fatalf("attachments = %d, want 1", len(payload.Attachments))
	}
	att := payload.Attachments[0]
	if att.CVE != "CVE-2019-10744" || att.Package != "pkg:npm/lodash" ||
		att.Project != "acme-web" || att.Severity != "high" ||
		att.Title != "Prototype pollution in lodash" {
		t.Errorf("delivered attachment = %+v, mapping wrong", att)
	}

	// Signature must cover the exact raw bytes the server received.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotPayload)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(gotHeader), []byte(want)) {
		t.Errorf("signature = %q, want %q", gotHeader, want)
	}
}
