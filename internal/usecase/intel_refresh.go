package usecase

import (
	"context"
	"sync"
	"time"
)

const (
	// intelRefreshTimeout bounds one background refresh. The EPSS and KEV
	// providers run one after another, so the budget covers both client
	// timeouts.
	intelRefreshTimeout = 2 * time.Minute
	// intelRetryBackoff keeps a CVE that failed or stayed unresolved from
	// starting a new refresh on every detail read.
	intelRetryBackoff = 5 * time.Minute
)

// intelRefresher runs intel refreshes off the request path. It keeps at most
// one refresh in flight per CVE and holds a CVE back for intelRetryBackoff
// after an attempt that errored or left the CVE without a record. The zero
// value is ready to use.
type intelRefresher struct {
	mu         sync.Mutex
	inflight   map[string]struct{}
	retryAfter map[string]time.Time
	// now overrides the clock in tests; nil means time.Now.
	now func() time.Time
	// wg tracks background refreshes so tests can wait for them.
	wg sync.WaitGroup
}

// schedule starts a background refresh of cve unless one is already running
// or the CVE is inside its backoff window. It returns without waiting on the
// network. The refresh runs on a context detached from ctx, so a request that
// ends early does not cancel the fetch.
func (r *intelRefresher) schedule(ctx context.Context, store IntelStore, cve string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, busy := r.inflight[cve]; busy {
		return
	}
	if until, ok := r.retryAfter[cve]; ok && r.clock().Before(until) {
		return
	}
	if r.inflight == nil {
		r.inflight = make(map[string]struct{})
	}
	r.inflight[cve] = struct{}{}
	r.wg.Add(1)
	go r.run(context.WithoutCancel(ctx), store, cve)
}

func (r *intelRefresher) run(ctx context.Context, store IntelStore, cve string) {
	defer r.wg.Done()
	ctx, cancel := context.WithTimeout(ctx, intelRefreshTimeout)
	defer cancel()

	err := store.Refresh(ctx, []string{cve})
	_, _, resolved := store.Lookup(cve)

	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.inflight, cve)
	if err != nil || !resolved {
		if r.retryAfter == nil {
			r.retryAfter = make(map[string]time.Time)
		}
		r.retryAfter[cve] = r.clock().Add(intelRetryBackoff)
		return
	}
	delete(r.retryAfter, cve)
}

// clock reads the refresher's time source. Callers hold mu.
func (r *intelRefresher) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}
