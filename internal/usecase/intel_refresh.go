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
	// intelRetryPruneAt is the retryAfter size at which expired entries are
	// swept before a new one is added. Entries only live for
	// intelRetryBackoff, so the map stays near the number of distinct CVEs
	// that failed within one backoff window.
	intelRetryPruneAt = 1024
	// intelRefreshWorkers bounds the refreshes running at once, and with them
	// the outbound feed requests a burst of finding reads can start.
	intelRefreshWorkers = 4
	// intelRefreshQueue bounds the refreshes waiting for a worker. A schedule
	// beyond it is skipped and the cached value is served; a later read tries
	// again.
	intelRefreshQueue = 256
)

// intelRefresher runs intel refreshes off the request path. It keeps at most
// one refresh queued or running per CVE, runs at most intelRefreshWorkers at
// once with intelRefreshQueue waiting, and holds a CVE back for
// intelRetryBackoff after an attempt that errored or left the CVE without a
// record. The zero value is ready to use.
type intelRefresher struct {
	mu         sync.Mutex
	inflight   map[string]struct{}
	retryAfter map[string]time.Time
	// queue holds the refreshes waiting for a worker; running counts the
	// workers draining it. A worker exits when the queue is empty, so an idle
	// refresher holds no goroutine.
	queue   []intelJob
	running int
	// now overrides the clock in tests; nil means time.Now.
	now func() time.Time
	// wg tracks background refreshes so tests can wait for them.
	wg sync.WaitGroup
}

// intelJob is one queued refresh. The context is detached from the request
// that scheduled it.
type intelJob struct {
	ctx   context.Context
	store IntelStore
	cve   string
}

// schedule queues a background refresh of cve unless one is already queued or
// running, the CVE is inside its backoff window, or the queue is full. It
// returns without waiting on the network. The refresh runs on a context
// detached from ctx, so a request that ends early does not cancel the fetch.
func (r *intelRefresher) schedule(ctx context.Context, store IntelStore, cve string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, busy := r.inflight[cve]; busy {
		return
	}
	if until, ok := r.retryAfter[cve]; ok {
		if r.clock().Before(until) {
			return
		}
		delete(r.retryAfter, cve)
	}
	if len(r.queue) >= intelRefreshQueue {
		return
	}
	if r.inflight == nil {
		r.inflight = make(map[string]struct{})
	}
	r.inflight[cve] = struct{}{}
	r.queue = append(r.queue, intelJob{ctx: context.WithoutCancel(ctx), store: store, cve: cve})
	if r.running < intelRefreshWorkers {
		r.running++
		r.wg.Add(1)
		go r.work()
	}
}

// work runs queued refreshes until the queue is empty.
func (r *intelRefresher) work() {
	defer r.wg.Done()
	for {
		r.mu.Lock()
		if len(r.queue) == 0 {
			r.running--
			r.mu.Unlock()
			return
		}
		job := r.queue[0]
		r.queue[0] = intelJob{}
		r.queue = r.queue[1:]
		r.mu.Unlock()
		r.run(job.ctx, job.store, job.cve)
	}
}

func (r *intelRefresher) run(ctx context.Context, store IntelStore, cve string) {
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
		if len(r.retryAfter) >= intelRetryPruneAt {
			r.pruneExpiredLocked()
		}
		r.retryAfter[cve] = r.clock().Add(intelRetryBackoff)
		return
	}
	delete(r.retryAfter, cve)
}

// pruneExpiredLocked drops retry entries whose backoff has ended; schedule
// treats them as absent anyway. Callers hold mu.
func (r *intelRefresher) pruneExpiredLocked() {
	now := r.clock()
	for cve, until := range r.retryAfter {
		if !now.Before(until) {
			delete(r.retryAfter, cve)
		}
	}
}

// clock reads the refresher's time source. Callers hold mu.
func (r *intelRefresher) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}
