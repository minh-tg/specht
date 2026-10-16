package server

import (
	"crypto/sha256"
	"sync"
	"time"
)

const (
	// loginFreeFailures is how many consecutive failed password logins an
	// account takes before the first wait starts.
	loginFreeFailures = 3
	// loginDelayBase is the first wait; each further failure doubles it.
	loginDelayBase = time.Second
	// loginDelayMax caps the wait. There is no lockout: a legitimate user
	// always gets back in within a minute.
	loginDelayMax = 60 * time.Second
	// loginDelayDecay is how long an account must go without a failed login
	// before its counter drops to zero.
	loginDelayDecay = 15 * time.Minute
)

// loginAttempts is the failure state of one account.
type loginAttempts struct {
	failures     int
	lastFailure  time.Time
	blockedUntil time.Time
}

// loginEvictSample is how many entries a full store examines when it looks
// for one to evict. Map iteration starts at a random position, so a bounded
// walk is a cheap random sample and the lookup stays O(1).
const loginEvictSample = 64

// loginDelay slows password guessing against one account, whichever address
// the guesses come from. It is keyed by the normalized email and counts
// unknown emails exactly like known ones, so the delay cannot be used to find
// out whether an account exists. The map is bounded, so a flood of made-up
// emails cannot grow memory, and no two emails ever share a counter: when the
// map is full a newcomer takes the slot of an entry that carries no wait yet,
// or, if every entry is waiting, is not tracked at all (the per-IP login
// bucket still applies). It is safe for concurrent use.
type loginDelay struct {
	mu       sync.Mutex
	items    map[string]*loginAttempts
	max      int
	lastFull time.Time
	now      func() time.Time
}

func newLoginDelay() *loginDelay {
	return &loginDelay{
		items: make(map[string]*loginAttempts),
		max:   maxLiveBuckets,
		now:   time.Now,
	}
}

// loginTicket identifies the attempt that begin admitted, so succeed or
// refund can undo its charge. An empty key marks an attempt on an email the
// full store did not track; there is nothing to undo for it.
type loginTicket struct {
	key string
}

// attemptKey hashes the email so a request cannot make the store hold
// megabytes per key (the body cap is 1 MiB) and no address is kept in memory.
func attemptKey(email string) string {
	sum := sha256.Sum256([]byte(email))
	return string(sum[:])
}

// loginWait is the wait after the nth consecutive failure.
func loginWait(failures int) time.Duration {
	if failures < loginFreeFailures {
		return 0
	}
	exp := failures - loginFreeFailures
	if exp >= 6 { // 1s << 6 is already past the cap
		return loginDelayMax
	}
	return min(loginDelayBase<<exp, loginDelayMax)
}

// begin admits or refuses one password attempt for the normalized email. A
// refused attempt reports how long the account is still waiting and is not
// counted. An admitted attempt is counted as a failure at once, before the
// password is checked, so a burst of parallel guesses cannot all slip in ahead
// of the first recorded failure; succeed undoes the charge.
func (d *loginDelay) begin(email string) (ticket loginTicket, retryAfter time.Duration, ok bool) {
	now := d.now()
	key := attemptKey(email)

	d.mu.Lock()
	defer d.mu.Unlock()
	st, found := d.items[key]
	if found && now.Before(st.blockedUntil) {
		return loginTicket{}, st.blockedUntil.Sub(now), false
	}
	if !found {
		if st = d.admitNew(key, now); st == nil {
			return loginTicket{}, 0, true
		}
	}
	if now.Sub(st.lastFailure) > loginDelayDecay {
		*st = loginAttempts{}
	}
	st.failures++
	st.lastFailure = now
	if wait := loginWait(st.failures); wait > 0 {
		st.blockedUntil = now.Add(wait)
	}
	return loginTicket{key: key}, 0, true
}

// admitNew creates the entry for a key the store has not seen. At the cap it
// first sweeps entries whose counter has decayed (at most once a second, so a
// flood cannot make every request walk the map), then evicts the stalest
// entry in a sample that carries no wait yet. It returns nil when every
// sampled entry is waiting: the email goes untracked rather than sharing a
// counter with strangers.
func (d *loginDelay) admitNew(key string, now time.Time) *loginAttempts {
	if len(d.items) >= d.max && now.Sub(d.lastFull) >= minFullSweepGap {
		d.sweep(now)
		d.lastFull = now
	}
	if len(d.items) >= d.max {
		victim, found := d.evictionCandidate(now)
		if !found {
			return nil
		}
		delete(d.items, victim)
	}
	st := &loginAttempts{}
	d.items[key] = st
	return st
}

// sweep drops every entry whose counter has decayed to zero.
func (d *loginDelay) sweep(now time.Time) {
	for k, st := range d.items {
		if now.Sub(st.lastFailure) > loginDelayDecay && !now.Before(st.blockedUntil) {
			delete(d.items, k)
		}
	}
}

// evictionCandidate picks, from a bounded sample, the entry that failed
// longest ago among those that have not reached a wait and are not blocked.
func (d *loginDelay) evictionCandidate(now time.Time) (key string, ok bool) {
	var oldest time.Time
	seen := 0
	for k, st := range d.items {
		if st.failures < loginFreeFailures && !now.Before(st.blockedUntil) && (!ok || st.lastFailure.Before(oldest)) {
			key, oldest, ok = k, st.lastFailure, true
		}
		if seen++; seen >= loginEvictSample {
			break
		}
	}
	return key, ok
}

// succeed resets the counter after a correct password.
func (d *loginDelay) succeed(t loginTicket) {
	if t.key == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.items, t.key)
}

// refund gives back the one charge begin took for an attempt that never
// reached a password comparison, leaving the account's other failures alone.
func (d *loginDelay) refund(t loginTicket) {
	if t.key == "" {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if st, found := d.items[t.key]; found && st.failures > 0 {
		st.failures--
		if st.failures < loginFreeFailures {
			st.blockedUntil = time.Time{}
		}
	}
}

// accountCount reports how many accounts hold state. Tests use it to assert
// the bound.
func (d *loginDelay) accountCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.items)
}
