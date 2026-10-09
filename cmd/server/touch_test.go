package main

import (
	"fmt"
	"testing"
	"time"
)

func newTestThrottle(start time.Time) (*touchThrottle, *time.Time) {
	now := start
	th := newTouchThrottle(time.Minute)
	th.now = func() time.Time { return now }
	return th, &now
}

func TestTouchThrottle_AllowsOneWritePerKeyPerInterval(t *testing.T) {
	th, now := newTestThrottle(time.Unix(1_000_000, 0))

	if !th.due("key-a") {
		t.Fatal("first use of a key must be recorded")
	}
	if th.due("key-a") {
		t.Fatal("a second use inside the interval must not write again")
	}
	if !th.due("key-b") {
		t.Fatal("another key has its own budget")
	}

	*now = now.Add(59 * time.Second)
	if th.due("key-a") {
		t.Fatal("still inside the interval")
	}
	*now = now.Add(2 * time.Second)
	if !th.due("key-a") {
		t.Fatal("after the interval the key is due again")
	}
}

func TestTouchThrottle_ReleaseLetsAFailedWriteRetry(t *testing.T) {
	th, _ := newTestThrottle(time.Unix(1_000_000, 0))

	if !th.due("key-a") {
		t.Fatal("first use must be due")
	}
	th.release("key-a")
	if !th.due("key-a") {
		t.Fatal("a write that failed must not suppress the next attempt")
	}
}

func TestTouchThrottle_SweepsAtMostOncePerInterval(t *testing.T) {
	th, clock := newTestThrottle(time.Unix(1000, 0))
	for i := 0; i < touchThrottlePruneAt; i++ {
		th.due(fmt.Sprintf("key-%d", i))
	}

	// Every entry is stale once the interval has passed, so the next write that
	// reaches the threshold sweeps them all.
	*clock = clock.Add(2 * time.Minute)
	th.due("first")
	if len(th.seen) != 1 {
		t.Fatalf("stale keys should be swept, have %d entries", len(th.seen))
	}

	// A stale entry planted inside the same interval survives a burst of writes:
	// the sweep already ran for this interval.
	th.seen["planted"] = clock.Add(-time.Hour)
	for i := 0; i < touchThrottlePruneAt; i++ {
		th.due(fmt.Sprintf("burst-%d", i))
	}
	if _, ok := th.seen["planted"]; !ok {
		t.Fatal("the map was swept twice within one interval")
	}

	*clock = clock.Add(2 * time.Minute)
	th.due("later")
	if _, ok := th.seen["planted"]; ok {
		t.Fatal("a stale entry should be swept once the interval has passed")
	}
}

func TestTouchThrottle_ForgetsStaleKeysSoMemoryStaysBounded(t *testing.T) {
	th, now := newTestThrottle(time.Unix(1_000_000, 0))
	for i := 0; i < touchThrottlePruneAt+10; i++ {
		th.due(string(rune('a'+i%26)) + time.Duration(i).String())
	}
	*now = now.Add(2 * time.Minute)

	th.due("fresh")

	th.mu.Lock()
	defer th.mu.Unlock()
	if len(th.seen) > 2 {
		t.Fatalf("entries older than the interval must be pruned, have %d", len(th.seen))
	}
}
