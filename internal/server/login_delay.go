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

// loginDelay slows password guessing against one account, whichever address
// the guesses come from. It is keyed by the normalized email and counts
// unknown emails exactly like known ones, so the delay cannot be used to find
// out whether an account exists. State lives in a bounded keyedStore, so a
// flood of made-up emails cannot grow memory. It is safe for concurrent use.
type loginDelay struct {
	mu    sync.Mutex
	store *keyedStore[*loginAttempts]
	now   func() time.Time
}

func newLoginDelay() *loginDelay {
	return &loginDelay{
		store: newKeyedStore(maxLiveBuckets, loginDelayDecay, func() *loginAttempts { return &loginAttempts{} }),
		now:   time.Now,
	}
}

// loginTicket identifies the attempt that begin admitted, so succeed can undo
// its charge.
type loginTicket struct {
	key      string
	overflow bool
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
	if st, found := d.store.peek(key); found && now.Before(st.blockedUntil) {
		return loginTicket{}, st.blockedUntil.Sub(now), false
	}
	st, overflow := d.store.acquire(key, now)
	if now.Sub(st.lastFailure) > loginDelayDecay {
		*st = loginAttempts{}
	}
	st.failures++
	st.lastFailure = now
	if wait := loginWait(st.failures); wait > 0 {
		st.blockedUntil = now.Add(wait)
	}
	return loginTicket{key: key, overflow: overflow}, 0, true
}

// succeed resets the counter after a correct password. An account that shares
// the overflow counter only gives back its own charge, because the counter
// also holds other accounts' failures.
func (d *loginDelay) succeed(t loginTicket) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !t.overflow {
		d.store.remove(t.key)
		return
	}
	if st, found := d.store.peek(t.key); found && st.failures > 0 {
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
	return d.store.len()
}
