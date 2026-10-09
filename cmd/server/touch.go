package main

import (
	"sync"
	"time"
)

const (
	// apiKeyTouchInterval bounds how stale a key's last_used_at can be.
	apiKeyTouchInterval = time.Minute
	// touchThrottlePruneAt is the map size past which expired entries are
	// dropped on the next write, so memory follows the number of keys in use.
	touchThrottlePruneAt = 1024
)

// touchThrottle lets a key's last_used_at be written at most once per
// interval, per process. Without it every authenticated request adds a
// database write to a single hot row. Only keys that already passed every
// check are ever recorded, so unauthenticated traffic cannot grow it.
type touchThrottle struct {
	mu        sync.Mutex
	interval  time.Duration
	seen      map[string]time.Time
	now       func() time.Time
	lastPrune time.Time
}

func newTouchThrottle(interval time.Duration) *touchThrottle {
	return &touchThrottle{interval: interval, seen: map[string]time.Time{}, now: time.Now}
}

// due reports whether id should be written now and, if so, records the attempt.
func (t *touchThrottle) due(id string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if last, ok := t.seen[id]; ok && now.Sub(last) < t.interval {
		return false
	}
	// The full scan runs at most once per interval, so a map that is large but
	// still fresh does not turn every write into an O(n) pass.
	if len(t.seen) >= touchThrottlePruneAt && now.Sub(t.lastPrune) >= t.interval {
		t.lastPrune = now
		for k, last := range t.seen {
			if now.Sub(last) >= t.interval {
				delete(t.seen, k)
			}
		}
	}
	t.seen[id] = now
	return true
}

// release forgets an attempt whose write failed so the next request retries.
func (t *touchThrottle) release(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.seen, id)
}
