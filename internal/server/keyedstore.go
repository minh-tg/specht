package server

import "time"

const (
	// maxLiveBuckets caps the entries one limiter keeps. A flood of distinct
	// keys (an IPv6 range, random emails) otherwise grows the map by one
	// entry per request until the next sweep.
	maxLiveBuckets = 100_000

	// minFullSweepGap spaces the sweeps a full store runs on demand, so a
	// flood of new keys cannot make every request walk the whole map.
	minFullSweepGap = time.Second
)

type keyedEntry[V any] struct {
	value    V
	lastSeen time.Time
}

// keyedStore is a bounded map of per-key state with idle expiry. When it is
// full and a sweep frees nothing, keys without an entry share one overflow
// entry: the flood is throttled together and no live entry is evicted. It is
// not safe for concurrent use; the owner holds its own lock around every call.
type keyedStore[V any] struct {
	items     map[string]*keyedEntry[V]
	max       int
	ttl       time.Duration
	create    func() V
	lastSweep time.Time
	lastFull  time.Time
	overflow  *keyedEntry[V]
}

func newKeyedStore[V any](max int, ttl time.Duration, create func() V) *keyedStore[V] {
	return &keyedStore[V]{items: make(map[string]*keyedEntry[V]), max: max, ttl: ttl, create: create}
}

func (s *keyedStore[V]) len() int { return len(s.items) }

func (s *keyedStore[V]) sweep(now time.Time) {
	for k, e := range s.items {
		if now.Sub(e.lastSeen) > s.ttl {
			delete(s.items, k)
		}
	}
	if s.overflow != nil && now.Sub(s.overflow.lastSeen) > s.ttl {
		s.overflow = nil
	}
}

// acquire returns the state for key, creating it when there is room. The
// second result reports that the shared overflow entry was returned instead.
func (s *keyedStore[V]) acquire(key string, now time.Time) (V, bool) {
	if now.Sub(s.lastSweep) >= s.ttl {
		s.sweep(now)
		s.lastSweep = now
	}
	if e, ok := s.items[key]; ok {
		e.lastSeen = now
		return e.value, false
	}
	if len(s.items) >= s.max && now.Sub(s.lastFull) >= minFullSweepGap {
		s.sweep(now)
		s.lastFull = now
	}
	if len(s.items) >= s.max {
		if s.overflow == nil {
			s.overflow = &keyedEntry[V]{value: s.create()}
		}
		s.overflow.lastSeen = now
		return s.overflow.value, true
	}
	e := &keyedEntry[V]{value: s.create(), lastSeen: now}
	s.items[key] = e
	return e.value, false
}

// peek returns the state a request for key would be judged against without
// creating or touching anything: the key's own entry, or the overflow entry
// while the store is full. ok is false when the key has no state yet.
func (s *keyedStore[V]) peek(key string) (v V, ok bool) {
	if e, found := s.items[key]; found {
		return e.value, true
	}
	if s.overflow != nil && len(s.items) >= s.max {
		return s.overflow.value, true
	}
	return v, false
}

// remove drops the entry for key, if any.
func (s *keyedStore[V]) remove(key string) { delete(s.items, key) }
