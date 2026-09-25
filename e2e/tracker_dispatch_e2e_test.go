//go:build e2e

package e2e

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// trackerEvent decodes one webhook delivery. tracker.Event marshals with Go
// field names (the struct carries no json tags), so the keys are
// capitalized — the payload contract a webhook consumer sees.
type trackerEvent struct {
	Type        string         `json:"Type"`
	FindingID   string         `json:"FindingID"`
	ProjectSlug string         `json:"ProjectSlug"`
	Severity    string         `json:"Severity"`
	Title       string         `json:"Title"`
	Fingerprint string         `json:"Fingerprint"`
	FindingKind string         `json:"FindingKind"`
	OccurredAt  string         `json:"OccurredAt"`
	Changes     map[string]any `json:"Changes"`
}

// trackerDeliveries returns signature-verified deliveries of one event type
// posted after the given sink watermark.
func trackerDeliveries(t *testing.T, watermark int, eventType string) []trackerEvent {
	t.Helper()
	var out []trackerEvent
	snapshot := fakes.trackerSink.snapshot()
	for _, req := range snapshot[watermark:] {
		if req.Header.Get("X-Tracker-Event") != eventType {
			continue
		}
		mac := hmac.New(sha256.New, []byte(e2eWebhookSecret))
		_, _ = mac.Write(req.Body)
		require.Equal(t, "sha256="+hex.EncodeToString(mac.Sum(nil)),
			req.Header.Get("X-Specht-Signature"),
			"every delivery carries a verifiable signature")
		var ev trackerEvent
		require.NoErrorf(t, json.Unmarshal(req.Body, &ev), "payload decodes: %s", req.Body)
		out = append(out, ev)
	}
	return out
}

// waitForTrackerDeliveries polls until at least min deliveries of one type
// arrived after the watermark.
func waitForTrackerDeliveries(t *testing.T, watermark int, eventType string, min int) []trackerEvent {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	var found []trackerEvent
	for time.Now().Before(deadline) {
		found = trackerDeliveries(t, watermark, eventType)
		if len(found) >= min {
			return found
		}
		time.Sleep(250 * time.Millisecond)
	}
	require.FailNowf(t, "tracker deliveries never arrived",
		"event=%s want>=%d got=%d", eventType, min, len(found))
	return found
}

// TestE2E_TrackerDispatchLifecycle closes BP-51: finding lifecycle events
// reach the webhook transport — created on ingest, verified_fixed when the
// auto-fix writer closes findings, regression when a complete rescan
// reintroduces them — each delivery signed and carrying the routing
// payload.
func TestE2E_TrackerDispatchLifecycle(t *testing.T) {
	slug := newProject(t, "tracker-lifecycle")
	scope := map[string]any{"branch": "main", "commit_sha": baseSHA}

	// 1. Created: the first scan materializes findings.
	w0 := fakes.trackerSink.count()
	first := ingestRaw(t, slug, "trivy", "trivy-alpine-scan.json", scope)
	require.Equal(t, 2, first.TotalFindings)

	created := waitForTrackerDeliveries(t, w0, "created", 2)
	createdIDs := map[string]bool{}
	for _, ev := range created {
		createdIDs[ev.FindingID] = true
		require.Equal(t, slug, ev.ProjectSlug, "routing carries the project slug")
		require.NotEmpty(t, ev.Severity)
		require.NotEmpty(t, ev.Fingerprint)
		require.NotEmpty(t, ev.FindingKind)
		require.NotEmpty(t, ev.OccurredAt)
	}

	// 2. Verified fixed: an equivalent complete scan that omits both
	// findings closes them (ADR-018) and announces each closure.
	w1 := fakes.trackerSink.count()
	second := ingestRaw(t, slug, "trivy", "trivy-empty-scan.json", scope)
	require.Zero(t, second.TotalFindings)
	for _, f := range listScanFindings(t, slug) {
		require.Equal(t, "fixed", f.State)
	}

	fixed := waitForTrackerDeliveries(t, w1, "verified_fixed", 2)
	require.Len(t, fixed, 2, "one verified_fixed delivery per closed finding")
	for _, ev := range fixed {
		require.True(t, createdIDs[ev.FindingID],
			"the closure announces the same finding the creation did")
	}

	// 3. Regression: the full scan reintroduces both findings (state
	// reopens) and dispatches regression for them; the six additional CVEs
	// arrive as fresh created events.
	w2 := fakes.trackerSink.count()
	third := ingestRaw(t, slug, "trivy", "trivy-alpine-full.json", scope)
	require.GreaterOrEqual(t, third.TotalFindings, 8)

	regressed := waitForTrackerDeliveries(t, w2, "regression", 2)
	regressedIDs := map[string]bool{}
	for _, ev := range regressed {
		regressedIDs[ev.FindingID] = true
		require.True(t, createdIDs[ev.FindingID],
			"regression announces a finding this project created")
	}
	require.Len(t, regressedIDs, 2, "both closed findings regressed")

	states := map[string]string{}
	for _, f := range listScanFindings(t, slug) {
		states[f.ID] = f.State
	}
	for id := range createdIDs {
		require.Equal(t, "reopened", states[id],
			"a regressing fixed finding reopens")
	}
	waitForTrackerDeliveries(t, w2, "created", 2) // the new CVEs fan out too
}
