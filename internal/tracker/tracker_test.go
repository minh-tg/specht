package tracker

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInProcessTracker_CreateAndVerifyFixed(t *testing.T) {
	tr := NewInProcessTracker(nil)

	created, err := tr.CreateIssue(context.Background(), Event{
		Type:        EventCreated,
		FindingID:   "find-1",
		ProjectSlug: "my-app",
		Severity:    "high",
		Title:       "CVE-2024-1234",
		Fingerprint: "fp1",
		FindingKind: "sca",
		OccurredAt:  time.Now(),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, created)

	issues := tr.Issues()
	require.Len(t, issues, 1)
	assert.Equal(t, "open", issues[0].State)
	assert.Equal(t, "find-1", issues[0].FindingID)

	err = tr.UpdateIssue(context.Background(), created, Event{
		Type:        EventVerifiedFixed,
		FindingID:   "find-1",
		ProjectSlug: "my-app",
		OccurredAt:  time.Now(),
	})
	require.NoError(t, err)

	issues = tr.Issues()
	require.Len(t, issues, 1)
	assert.Equal(t, "closed", issues[0].State)
	assert.Len(t, issues[0].Transitions, 1)
	assert.Equal(t, "open", issues[0].Transitions[0].From)
	assert.Equal(t, "closed", issues[0].Transitions[0].To)
}

func TestInProcessTracker_RegressionReopens(t *testing.T) {
	tr := NewInProcessTracker(nil)

	_, err := tr.CreateIssue(context.Background(), Event{
		Type:        EventCreated,
		FindingID:   "find-reg",
		ProjectSlug: "app",
		Severity:    "critical",
		Title:       "CVE-2024-9999",
		Fingerprint: "fp2",
		FindingKind: "sca",
	})
	require.NoError(t, err)

	// Regression: finding reappears → reopened.
	err = tr.UpdateIssue(context.Background(), "", Event{
		Type:        EventRegression,
		FindingID:   "find-reg",
		ProjectSlug: "app",
		OccurredAt:  time.Now(),
	})
	require.NoError(t, err)

	issues := tr.Issues()
	require.Len(t, issues, 1)
	assert.Equal(t, "reopened", issues[0].State)
	assert.Len(t, issues[0].Transitions, 1)
	assert.Equal(t, "open", issues[0].Transitions[0].From)
	assert.Equal(t, "reopened", issues[0].Transitions[0].To)
}

func TestNoopTracker(t *testing.T) {
	n := NoopTracker{}
	id, err := n.CreateIssue(context.Background(), Event{Type: EventCreated, FindingID: "f1"})
	require.NoError(t, err)
	assert.Equal(t, IssueID(""), id)
	assert.NoError(t, n.UpdateIssue(context.Background(), "", Event{Type: EventRegression, FindingID: "f1"}))
	assert.Equal(t, "noop", n.Name())
}

func TestResolveConfig(t *testing.T) {
	c := ResolveConfig()
	assert.Equal(t, "noop", c.Provider)
}

// blockingTracker records invocations and blocks the FIRST call until
// released, simulating a tracker whose initial delivery stalls (e.g. a
// webhook POST against a dead endpoint with a long client timeout).
// Subsequent calls complete immediately so a test can observe whether they
// are serialized behind the stalled one.
type blockingTracker struct {
	mu       sync.Mutex
	calls    int
	released chan struct{}
}

func (b *blockingTracker) CreateIssue(ctx context.Context, event Event) (IssueID, error) {
	return "", b.block(ctx)
}

func (b *blockingTracker) UpdateIssue(ctx context.Context, issueID IssueID, event Event) error {
	return b.block(ctx)
}

func (b *blockingTracker) Name() string { return "blocking" }

func (b *blockingTracker) block(ctx context.Context) error {
	b.mu.Lock()
	first := b.calls == 0
	b.calls++
	b.mu.Unlock()
	if !first {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-b.released:
		return nil
	}
}

// TestDispatcher_ConcurrentEventsNotBlockedBySlowTracker pins that Dispatch
// releases its lock (or never holds it) across tracker I/O: while a first
// event is still being delivered to a slow tracker, a second, concurrent
// Dispatch must start and finish without waiting for the first delivery.
func TestDispatcher_ConcurrentEventsNotBlockedBySlowTracker(t *testing.T) {
	slow := &blockingTracker{released: make(chan struct{})}
	d := NewDispatcher(slow, slog.New(slog.NewTextHandler(io.Discard, nil)))

	// First dispatch blocks inside the slow tracker's CreateIssue.
	firstDone := make(chan struct{})
	go func() {
		defer close(firstDone)
		d.Dispatch(context.Background(), Event{Type: EventCreated, FindingID: "f1"})
	}()
	require.Eventually(t, func() bool {
		slow.mu.Lock()
		defer slow.mu.Unlock()
		return slow.calls == 1
	}, 2*time.Second, 10*time.Millisecond, "first dispatch never reached the tracker")

	// A second dispatch must not wait on the first: the lock may not be
	// held across the (still in-flight) first delivery.
	secondDone := make(chan struct{})
	go func() {
		defer close(secondDone)
		d.Dispatch(context.Background(), Event{Type: EventCreated, FindingID: "f2"})
	}()

	select {
	case <-secondDone:
		// Pass: the second event was delivered concurrently.
	case <-time.After(2 * time.Second):
		t.Fatal("second Dispatch blocked behind the first in-flight delivery; " +
			"Dispatcher.mu must not be held across tracker I/O")
	}

	// Unblock the first delivery so the test exits cleanly.
	close(slow.released)
	select {
	case <-firstDone:
	case <-time.After(2 * time.Second):
		t.Fatal("first dispatch never returned after its tracker was released")
	}
}
