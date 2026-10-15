package cvedetail

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Cache row statuses.
const (
	StatusFound    = "found"
	StatusNotFound = "not_found"
	StatusPending  = "pending"
)

// Per-CVE provider statuses in an API response.
const (
	LookupFound    = "found"
	LookupNotFound = "not_found"
	LookupError    = "error"
	LookupPending  = "pending"
	LookupSkipped  = "skipped"
	LookupDisabled = "disabled"
)

// CacheEntry is one cached provider answer, or the placeholder a replica
// writes while it holds the fetch lease.
type CacheEntry struct {
	Provider   string
	CVEID      string
	Status     string
	Record     *Record
	FetchedAt  time.Time
	ExpiresAt  time.Time
	LeaseUntil *time.Time
}

// ProviderState is the last recorded outcome of one provider.
type ProviderState struct {
	Provider      string
	LastSuccessAt *time.Time
	LastErrorAt   *time.Time
	LastError     string
	BackoffUntil  *time.Time
}

// Store persists the cache, the fetch lease and the provider status. The
// PostgreSQL implementation lives in internal/repo.
type Store interface {
	ListCached(ctx context.Context, cveID string) ([]CacheEntry, error)
	// AcquireLease takes the fetch lease for one provider and CVE until the
	// given time. It reports false when another holder's lease is current or
	// a fresh answer exists.
	AcquireLease(ctx context.Context, provider, cveID string, now, until time.Time) (bool, error)
	// StoreAnswer writes a found or not_found answer and releases the lease.
	StoreAnswer(ctx context.Context, entry CacheEntry) error
	// ReleaseLease gives the lease up after a failed fetch and drops a
	// placeholder that never got an answer.
	ReleaseLease(ctx context.Context, provider, cveID string) error
	RecordSuccess(ctx context.Context, provider string, at time.Time) error
	RecordError(ctx context.Context, provider, kind string, at time.Time, backoffUntil time.Time) error
	ListProviderStates(ctx context.Context) ([]ProviderState, error)
	// Sweep deletes answers that expired before cutoff and returns how many.
	Sweep(ctx context.Context, cutoff time.Time) (int64, error)
}

// Config tunes a Resolver. Zero values take the defaults below.
type Config struct {
	TTL         time.Duration
	NegativeTTL time.Duration
	// LeaseTTL bounds how long a replica may hold a fetch before another
	// replica may take over. It must exceed the request timeout plus the
	// rate limiter's wait.
	LeaseTTL time.Duration
	// Rates holds the request rate per provider name, in requests per second.
	Rates map[string]float64
	// QueueSize bounds the jobs waiting for a worker; more are dropped.
	QueueSize int
	Workers   int
	// ErrorBackoff holds a provider back after a failure that gave no
	// Retry-After, and keeps a CVE whose fetch failed from being retried on
	// every read.
	ErrorBackoff time.Duration
	Now          func() time.Time
	Logger       *slog.Logger
}

// Defaults for Config.
const (
	DefaultTTL          = 24 * time.Hour
	DefaultNegativeTTL  = 6 * time.Hour
	DefaultLeaseTTL     = 2 * time.Minute
	DefaultQueueSize    = 64
	DefaultWorkers      = 2
	DefaultErrorBackoff = 5 * time.Minute
	// defaultRate applies to a provider the Rates map does not name.
	defaultRate = 1.0
)

type providerSlot struct {
	provider Provider
	limiter  *rate.Limiter
}

// Resolver serves cached provider answers and fetches missing ones in the
// background. It never calls a provider on the caller's goroutine.
type Resolver struct {
	cfg   Config
	store Store
	slots []providerSlot
	jobs  chan string

	mu         sync.Mutex
	queued     map[string]struct{}
	retryAfter map[string]time.Time

	startOnce sync.Once
	wg        sync.WaitGroup
}

// NewResolver builds a resolver over providers in lookup order. A resolver
// with no providers is valid and reports every provider disabled.
func NewResolver(store Store, cfg Config, providers ...Provider) *Resolver {
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultTTL
	}
	if cfg.NegativeTTL <= 0 {
		cfg.NegativeTTL = DefaultNegativeTTL
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = DefaultLeaseTTL
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = DefaultQueueSize
	}
	if cfg.Workers <= 0 {
		cfg.Workers = DefaultWorkers
	}
	if cfg.ErrorBackoff <= 0 {
		cfg.ErrorBackoff = DefaultErrorBackoff
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	r := &Resolver{
		cfg:        cfg,
		store:      store,
		jobs:       make(chan string, cfg.QueueSize),
		queued:     map[string]struct{}{},
		retryAfter: map[string]time.Time{},
	}
	for _, p := range providers {
		rps, ok := cfg.Rates[p.Name()]
		if !ok || rps <= 0 {
			rps = defaultRate
		}
		r.slots = append(r.slots, providerSlot{provider: p, limiter: rate.NewLimiter(rate.Limit(rps), 1)})
	}
	return r
}

// Enabled reports whether any provider is configured.
func (r *Resolver) Enabled() bool {
	return r != nil && len(r.slots) > 0
}

// Providers returns the configured provider names in lookup order.
func (r *Resolver) Providers() []string {
	if !r.Enabled() {
		return nil
	}
	out := make([]string, 0, len(r.slots))
	for _, s := range r.slots {
		out = append(out, s.provider.Name())
	}
	return out
}

// Start runs the fetch workers until ctx ends. Each fetch runs on a context
// detached from the request that scheduled it, so a client that disconnects
// does not cancel the fetch, but shutdown does.
func (r *Resolver) Start(ctx context.Context) {
	if !r.Enabled() {
		return
	}
	r.startOnce.Do(func() {
		for range r.cfg.Workers {
			r.wg.Add(1)
			go r.worker(ctx)
		}
	})
}

// Wait blocks until the workers stop; tests call it after cancelling Start's
// context.
func (r *Resolver) Wait() { r.wg.Wait() }

func (r *Resolver) worker(ctx context.Context) {
	defer r.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case cve := <-r.jobs:
			r.process(ctx, cve)
			r.mu.Lock()
			delete(r.queued, cve)
			r.mu.Unlock()
		}
	}
}

// Schedule queues a background fetch of cve. It returns false when the CVE is
// inside its retry backoff or the queue is full; the job is then dropped and
// a later read schedules it again.
func (r *Resolver) Schedule(cve string) bool {
	if !r.Enabled() || !ValidCVEID(cve) {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.cfg.Now()
	r.pruneLocked(now)
	if _, ok := r.queued[cve]; ok {
		return true
	}
	if until, ok := r.retryAfter[cve]; ok && now.Before(until) {
		return false
	}
	select {
	case r.jobs <- cve:
		r.queued[cve] = struct{}{}
		return true
	default:
		r.cfg.Logger.Warn("cve detail fetch queue full, dropping job", "cve", cve)
		return false
	}
}

// pruneLocked drops retry entries whose backoff has passed, so the map holds
// only CVEs that failed recently. Callers hold mu.
func (r *Resolver) pruneLocked(now time.Time) {
	for cve, until := range r.retryAfter {
		if !now.Before(until) {
			delete(r.retryAfter, cve)
		}
	}
}

// retryLen reports the size of the retry map; tests use it to check pruning.
func (r *Resolver) retryLen() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.retryAfter)
}

func (r *Resolver) inRetryBackoff(cve string, now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	until, ok := r.retryAfter[cve]
	return ok && now.Before(until)
}

func (r *Resolver) isQueued(cve string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.queued[cve]
	return ok
}

// process walks the providers in order for one CVE and stops at the first
// that has a record. Fresh cached answers are reused, a provider inside its
// shared backoff is skipped, and a lease held elsewhere means another replica
// is already walking this CVE.
func (r *Resolver) process(ctx context.Context, cve string) {
	entries, err := r.store.ListCached(ctx, cve)
	if err != nil {
		r.cfg.Logger.Warn("cve detail cache read failed", "cve", cve, "error", err)
		r.setRetry(cve)
		return
	}
	cached := make(map[string]CacheEntry, len(entries))
	for _, e := range entries {
		cached[e.Provider] = e
	}
	backoff := r.providerBackoffs(ctx)
	failed := false
	for _, slot := range r.slots {
		name := slot.provider.Name()
		now := r.cfg.Now()
		if e, ok := cached[name]; ok && e.Status != StatusPending && e.ExpiresAt.After(now) {
			if e.Status == StatusFound {
				return
			}
			continue
		}
		if until, ok := backoff[name]; ok && now.Before(until) {
			failed = true
			continue
		}
		got, err := r.store.AcquireLease(ctx, name, cve, now, now.Add(r.cfg.LeaseTTL))
		if err != nil {
			r.cfg.Logger.Warn("cve detail lease failed", "provider", name, "cve", cve, "error", err)
			failed = true
			continue
		}
		if !got {
			return
		}
		switch r.fetch(ctx, slot, cve) {
		case fetchFound:
			return
		case fetchNotFound:
			continue
		case fetchStopped:
			return
		default:
			failed = true
		}
	}
	if failed {
		r.setRetry(cve)
	}
}

type fetchOutcome int

const (
	fetchFound fetchOutcome = iota
	fetchNotFound
	fetchFailed
	fetchStopped
)

// fetch performs one rate-limited lookup while holding the lease and records
// its outcome.
func (r *Resolver) fetch(ctx context.Context, slot providerSlot, cve string) fetchOutcome {
	name := slot.provider.Name()
	if err := slot.limiter.Wait(ctx); err != nil {
		r.release(name, cve)
		return fetchStopped
	}
	rec, err := slot.provider.Lookup(ctx, cve)
	now := r.cfg.Now()
	// Writes after the lookup use a context that survives shutdown briefly,
	// so a finished fetch is not lost and a lease is not left behind.
	wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err == nil {
		rec.CVEID = cve
		rec = normalize(rec)
		if raw, mErr := json.Marshal(rec); mErr != nil || len(raw) > MaxRecordBytes {
			err = errRecordTooLarge
		}
	}
	switch {
	case err == nil:
		if sErr := r.store.StoreAnswer(wctx, CacheEntry{Provider: name, CVEID: cve, Status: StatusFound, Record: &rec, FetchedAt: now, ExpiresAt: now.Add(r.cfg.TTL)}); sErr != nil {
			r.cfg.Logger.Warn("cve detail cache write failed", "provider", name, "cve", cve, "error", sErr)
			r.release(name, cve)
			return fetchFailed
		}
		r.recordSuccess(wctx, name, now)
		return fetchFound
	case errors.Is(err, ErrNotFound):
		if sErr := r.store.StoreAnswer(wctx, CacheEntry{Provider: name, CVEID: cve, Status: StatusNotFound, FetchedAt: now, ExpiresAt: now.Add(r.cfg.NegativeTTL)}); sErr != nil {
			r.cfg.Logger.Warn("cve detail cache write failed", "provider", name, "cve", cve, "error", sErr)
			r.release(name, cve)
			return fetchFailed
		}
		r.recordSuccess(wctx, name, now)
		return fetchNotFound
	case ctx.Err() != nil:
		r.release(name, cve)
		return fetchStopped
	default:
		kind := ErrorKind(err)
		until := now.Add(r.cfg.ErrorBackoff)
		var rl *RateLimitedError
		if errors.As(err, &rl) {
			until = now.Add(rl.RetryAfter)
		}
		r.cfg.Logger.Warn("cve detail provider failed", "provider", name, "cve", cve, "kind", kind)
		if sErr := r.store.RecordError(wctx, name, kind, now, until); sErr != nil {
			r.cfg.Logger.Warn("cve detail status write failed", "provider", name, "error", sErr)
		}
		r.release(name, cve)
		return fetchFailed
	}
}

func (r *Resolver) release(name, cve string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := r.store.ReleaseLease(ctx, name, cve); err != nil {
		r.cfg.Logger.Warn("cve detail lease release failed", "provider", name, "cve", cve, "error", err)
	}
}

func (r *Resolver) recordSuccess(ctx context.Context, name string, at time.Time) {
	if err := r.store.RecordSuccess(ctx, name, at); err != nil {
		r.cfg.Logger.Warn("cve detail status write failed", "provider", name, "error", err)
	}
}

func (r *Resolver) setRetry(cve string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.retryAfter[cve] = r.cfg.Now().Add(r.cfg.ErrorBackoff)
}

// providerBackoffs reads the shared backoff each provider is under, so a rate
// limit one replica hit holds every replica back.
func (r *Resolver) providerBackoffs(ctx context.Context) map[string]time.Time {
	states, err := r.store.ListProviderStates(ctx)
	if err != nil {
		r.cfg.Logger.Warn("cve detail status read failed", "error", err)
		return nil
	}
	out := make(map[string]time.Time, len(states))
	for _, s := range states {
		if s.BackoffUntil != nil {
			out[s.Provider] = *s.BackoffUntil
		}
	}
	return out
}

// ProviderLookup is one provider's part in the answer for a CVE.
type ProviderLookup struct {
	Name      string
	Status    string
	FetchedAt *time.Time
	Record    *Record
}

// Lookup returns what the cache holds for cve, provider by provider. When need
// is false the report is complete and providers are not consulted: every
// configured provider reports skipped. When need is true, a missing or expired
// answer schedules a background fetch and reports pending. Lookup never calls
// a provider itself.
func (r *Resolver) Lookup(ctx context.Context, cve string, need bool) ([]ProviderLookup, error) {
	if !r.Enabled() {
		return nil, nil
	}
	out := make([]ProviderLookup, 0, len(r.slots))
	if !need {
		for _, s := range r.slots {
			out = append(out, ProviderLookup{Name: s.provider.Name(), Status: LookupSkipped})
		}
		return out, nil
	}
	entries, err := r.store.ListCached(ctx, cve)
	if err != nil {
		return nil, err
	}
	cached := make(map[string]CacheEntry, len(entries))
	for _, e := range entries {
		cached[e.Provider] = e
	}
	now := r.cfg.Now()
	queued := r.isQueued(cve)
	backedOff := r.inRetryBackoff(cve, now)
	refetch := false
	found := false
	for _, s := range r.slots {
		name := s.provider.Name()
		if found {
			out = append(out, ProviderLookup{Name: name, Status: LookupSkipped})
			continue
		}
		e, ok := cached[name]
		fetchedAt := e.FetchedAt
		switch {
		case ok && e.Status == StatusFound && e.Record != nil:
			found = true
			refetch = refetch || !e.ExpiresAt.After(now)
			out = append(out, ProviderLookup{Name: name, Status: LookupFound, FetchedAt: &fetchedAt, Record: e.Record})
		case ok && e.Status == StatusNotFound && e.ExpiresAt.After(now):
			out = append(out, ProviderLookup{Name: name, Status: LookupNotFound, FetchedAt: &fetchedAt})
		case ok && e.Status == StatusPending && e.LeaseUntil != nil && e.LeaseUntil.After(now):
			out = append(out, ProviderLookup{Name: name, Status: LookupPending})
		case backedOff && !queued:
			out = append(out, ProviderLookup{Name: name, Status: LookupError})
		default:
			refetch = true
			out = append(out, ProviderLookup{Name: name, Status: LookupPending})
		}
	}
	if refetch {
		r.Schedule(cve)
	}
	return out, nil
}

// ProviderStatus is one provider's line on the admin status page. It never
// carries a key, only whether one is configured.
type ProviderStatus struct {
	Name          string     `json:"name"`
	Enabled       bool       `json:"enabled"`
	KeyConfigured bool       `json:"key_configured"`
	LastSuccessAt *time.Time `json:"last_success_at"`
	LastError     *string    `json:"last_error"`
	LastErrorAt   *time.Time `json:"last_error_at"`
}

// keyed is implemented by providers that take an API key.
type keyed interface {
	KeyConfigured() bool
}

// KeyConfigured reports whether an API key is set.
func (p *NVD) KeyConfigured() bool { return p.APIKey != "" }

// KeyConfigured reports whether an API key is set.
func (p *VulnCheck) KeyConfigured() bool { return p.APIKey != "" }

// Status lists every known provider, configured ones first in lookup order,
// with the last outcome recorded by any replica. A nil resolver lists every
// provider as disabled without touching the database.
func (r *Resolver) Status(ctx context.Context) ([]ProviderStatus, error) {
	out := make([]ProviderStatus, 0, len(KnownProviders))
	seen := map[string]bool{}
	if r.Enabled() {
		for _, s := range r.slots {
			ps := ProviderStatus{Name: s.provider.Name(), Enabled: true}
			if k, ok := s.provider.(keyed); ok {
				ps.KeyConfigured = k.KeyConfigured()
			}
			seen[ps.Name] = true
			out = append(out, ps)
		}
	}
	for _, name := range KnownProviders {
		if !seen[name] {
			out = append(out, ProviderStatus{Name: name})
		}
	}
	if r == nil || r.store == nil {
		return out, nil
	}
	states, err := r.store.ListProviderStates(ctx)
	if err != nil {
		return out, err
	}
	byName := make(map[string]ProviderState, len(states))
	for _, s := range states {
		byName[s.Provider] = s
	}
	for i := range out {
		s, ok := byName[out[i].Name]
		if !ok {
			continue
		}
		out[i].LastSuccessAt = s.LastSuccessAt
		out[i].LastErrorAt = s.LastErrorAt
		if s.LastError != "" {
			kind := s.LastError
			out[i].LastError = &kind
		}
	}
	return out, nil
}
