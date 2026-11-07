package watcher

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/tracker"
)

type recordingTracker struct {
	mu     sync.Mutex
	events []tracker.Event
}

func (r *recordingTracker) Dispatch(_ context.Context, event tracker.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, event)
}

// A finding the watcher files reaches the tracker the way a scan's new finding does.
func TestPollOnce_TellsTheTrackerAboutACreatedFinding(t *testing.T) {
	deps := baseDeps()
	deps.Client.(*fakeClient).results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(context.Context, string, time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	sink := &recordingTracker{}
	var wg sync.WaitGroup
	deps.Tracker = sink
	deps.WG = &wg
	deps.ProjectSlug = func(context.Context, string) (string, error) { return "payments-api", nil }

	if _, err := PollOnce(context.Background(), deps); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	wg.Wait()

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) != 1 {
		t.Fatalf("events = %d, want 1", len(sink.events))
	}
	got := sink.events[0]
	if got.Type != tracker.EventCreated || got.ProjectSlug != "payments-api" || got.FindingKind != "cve_watcher" {
		t.Fatalf("event = %+v", got)
	}
	if got.FindingID != suppressingID {
		t.Fatalf("FindingID = %q, want the persisted id %q", got.FindingID, suppressingID)
	}
	if got.Title == "" || got.Severity == "" {
		t.Fatalf("event has no title or severity: %+v", got)
	}
}

// A re-poll of a finding that already exists is not news.
func TestPollOnce_DoesNotTellTheTrackerAboutAnExistingFinding(t *testing.T) {
	deps := baseDeps()
	deps.Client.(*fakeClient).results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(context.Context, string, time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	deps.Store.(*recordingStore).reportNoOp = true
	sink := &recordingTracker{}
	var wg sync.WaitGroup
	deps.Tracker = sink
	deps.WG = &wg

	if _, err := PollOnce(context.Background(), deps); err != nil {
		t.Fatalf("PollOnce: %v", err)
	}
	wg.Wait()

	sink.mu.Lock()
	defer sink.mu.Unlock()
	if len(sink.events) != 0 {
		t.Fatalf("events = %+v, want none", sink.events)
	}
}
