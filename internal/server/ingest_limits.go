package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/sync/semaphore"
)

const (
	// defaultRequestTimeout bounds every route except ingest.
	defaultRequestTimeout = 30 * time.Second
	// ingestWindow is how long one ingest may take once its body has arrived.
	ingestWindow = 2 * time.Minute
	// ingestBodyWindow is how long a caller has to send the body. The 25 MiB
	// cap needs about 0.85 MiB/s to fit; typical reports are far smaller. The
	// body is held by the caller's own gate while it arrives, never by a
	// global slot, so a slow upload costs nobody else anything.
	ingestBodyWindow = 30 * time.Second
	// ingestHeadBytes is how much of the body is read to find the project
	// before the caller is authorized. A body that does not name its project
	// within it is refused.
	ingestHeadBytes = 64 << 10
	// ingestWriteSlack is added to the write deadline so the response can
	// still be sent after a full-length upload and parse.
	ingestWriteSlack = 30 * time.Second
	// defaultIngestQueueWait is how long a request waits for a free ingest slot
	// or for memory budget before being told to retry.
	defaultIngestQueueWait = 15 * time.Second
	// DefaultIngestConcurrency is the number of ingests processed at once
	// when RouterConfig.IngestConcurrency is unset.
	DefaultIngestConcurrency = 8
	// DefaultIngestMemoryBudget is the memory all ingests in flight may charge
	// together when RouterConfig.IngestMemoryBudget is unset.
	DefaultIngestMemoryBudget int64 = 2 << 30
	// ingestBytesPerRawByte is what an ingest charges for each byte of its
	// report. Decoding a report holds the parsed structs, the format check's
	// copy and the redaction copy next to the bytes: the measured peak is 10 to
	// 30 times the report for real findings, and padding that slips past the
	// document scan costs more, so the charge is set well above both.
	ingestBytesPerRawByte = 64
)

// requestTimeout applies a context deadline to each request: def normally,
// and ingest for the report-upload call, which legitimately takes longer.
func requestTimeout(def, ingest time.Duration) func(http.Handler) http.Handler {
	short, long := middleware.Timeout(def), middleware.Timeout(ingest)
	return func(next http.Handler) http.Handler {
		shortNext, longNext := short(next), long(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost && r.URL.Path == ingestPath {
				longNext.ServeHTTP(w, r)
				return
			}
			shortNext.ServeHTTP(w, r)
		})
	}
}

// ingestPath is the report-upload endpoint the longer timeout applies to.
const ingestPath = "/api/v1/reports"

// ingestAdmission decides who may run an ingest and when. It holds the global
// concurrency slots, the memory budget, one gate per principal (a user or an
// API key) and one per project, so one caller, or one project with many
// callers, cannot use up what every tenant shares.
//
// An ingest passes three steps, in this order, and takes the next only when it
// holds the one before:
//
//  1. enter: a place in the caller's own gate, at most perPrincipal at a time,
//     held while the body is read. A caller past its limit waits in its own
//     queue and never delays another caller.
//  2. admit: once the whole body is in memory, a share of the caller's memory
//     allowance, the same for the project, a place in the project's gate, then
//     a global slot, then the global memory charge. These are held while the
//     report is decoded and stored.
//  3. release: everything is given back, in reverse order, on every path.
//
// The project gate is what keeps one tenant from filling every global slot:
// principals are cheap to add (a manager's session plus any number of keys),
// so a per-principal limit alone does not bound a project. A project holds at
// most perTenant slots and the same fraction of the memory budget, whatever
// the number of principals behind it.
//
// Authorization happens before enter, so a caller with no access to the project
// holds nothing. The body is read before the global slot is taken, so a slow
// upload holds only the caller's own gate.
type ingestAdmission struct {
	slots        chan struct{}
	perPrincipal int
	perTenant    int
	memory       *ingestMemory
	memoryShare  int64
	tenantShare  int64
	queueWait    time.Duration

	mu         sync.Mutex
	principals map[string]*gate
	tenants    map[string]*gate
}

// gate is one caller's or one project's share: places for concurrent ingests
// and an allowance of the memory budget. refs counts the requests using the
// gate, waiting or running, so the gate is dropped when the last one leaves.
type gate struct {
	refs   int
	places chan struct{}
	memory *semaphore.Weighted
}

// newIngestAdmission builds the admission control. A caller, and separately a
// project, may hold at most max(1, concurrency/2) places and the same fraction
// of the memory budget, so two callers of different projects can always run
// side by side when concurrency allows it.
func newIngestAdmission(concurrency int, memoryBudget int64, queueWait time.Duration) *ingestAdmission {
	if concurrency < 1 {
		concurrency = DefaultIngestConcurrency
	}
	memory := newIngestMemory(memoryBudget, queueWait)
	perPrincipal := max(1, concurrency/2)
	perTenant := max(1, concurrency/2)
	return &ingestAdmission{
		slots:        make(chan struct{}, concurrency),
		perPrincipal: perPrincipal,
		perTenant:    perTenant,
		memory:       memory,
		memoryShare:  max(1, memory.size/int64(concurrency)*int64(perPrincipal)),
		tenantShare:  max(1, memory.size/int64(concurrency)*int64(perTenant)),
		queueWait:    queueWait,
		principals:   map[string]*gate{},
		tenants:      map[string]*gate{},
	}
}

// ingestTicket is what an ingest holds while it runs. Its methods are used by
// one goroutine.
type ingestTicket struct {
	a         *ingestAdmission
	principal string
	tenant    string
	gate      *gate
	tenantG   *gate
	releases  []func()
}

// enter takes a place in the caller's gate, waiting up to the queue wait. It
// returns errIngestBusy when the caller's places stay taken, and the context's
// error when ctx ends first (the client went away). tenant is the id of the
// project the report is for, already authorized for this caller.
func (a *ingestAdmission) enter(ctx context.Context, principal, tenant string) (*ingestTicket, error) {
	a.mu.Lock()
	g := a.principals[principal]
	if g == nil {
		g = &gate{
			places: make(chan struct{}, a.perPrincipal),
			memory: semaphore.NewWeighted(a.memoryShare),
		}
		a.principals[principal] = g
	}
	g.refs++
	tg := a.tenants[tenant]
	if tg == nil {
		tg = &gate{
			places: make(chan struct{}, a.perTenant),
			memory: semaphore.NewWeighted(a.tenantShare),
		}
		a.tenants[tenant] = tg
	}
	tg.refs++
	a.mu.Unlock()

	t := &ingestTicket{a: a, principal: principal, tenant: tenant, gate: g, tenantG: tg}
	timer := time.NewTimer(a.queueWait)
	defer timer.Stop()
	select {
	case g.places <- struct{}{}:
		t.releases = append(t.releases, func() { <-g.places })
		return t, nil
	case <-timer.C:
		t.release()
		return nil, errIngestBusy
	case <-ctx.Done():
		t.release()
		return nil, ctx.Err()
	}
}

// admit takes what the ingest needs to run once its body of rawBytes is in
// memory: the caller's and the project's memory allowance, a place in the
// project's gate, a global slot and the global memory charge. The whole wait is
// bounded by one queue wait.
func (t *ingestTicket) admit(ctx context.Context, rawBytes int) error {
	a := t.a
	deadline := time.Now().Add(a.queueWait)
	charge := min(a.memory.charge(rawBytes), a.memoryShare)
	if err := waitUntil(ctx, deadline, func(ctx context.Context) error { return t.gate.memory.Acquire(ctx, charge) }); err != nil {
		return err
	}
	t.releases = append(t.releases, func() { t.gate.memory.Release(charge) })

	tenantCharge := min(charge, a.tenantShare)
	if err := waitUntil(ctx, deadline, func(ctx context.Context) error { return t.tenantG.memory.Acquire(ctx, tenantCharge) }); err != nil {
		return err
	}
	t.releases = append(t.releases, func() { t.tenantG.memory.Release(tenantCharge) })

	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case t.tenantG.places <- struct{}{}:
		t.releases = append(t.releases, func() { <-t.tenantG.places })
	case <-timer.C:
		return errIngestBusy
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case a.slots <- struct{}{}:
		t.releases = append(t.releases, func() { <-a.slots })
	case <-timer.C:
		return errIngestBusy
	case <-ctx.Done():
		return ctx.Err()
	}

	release, err := a.memory.acquireUntil(ctx, deadline, rawBytes)
	if err != nil {
		return err
	}
	t.releases = append(t.releases, release)
	return nil
}

// release gives back everything the ticket holds, newest first, and drops the
// caller's gate when it was the last user. It is safe to call more than once.
func (t *ingestTicket) release() {
	for i := len(t.releases) - 1; i >= 0; i-- {
		t.releases[i]()
	}
	t.releases = nil
	if t.gate == nil {
		return
	}
	a := t.a
	a.mu.Lock()
	t.gate.refs--
	if t.gate.refs == 0 {
		delete(a.principals, t.principal)
	}
	t.tenantG.refs--
	if t.tenantG.refs == 0 {
		delete(a.tenants, t.tenant)
	}
	a.mu.Unlock()
	t.gate, t.tenantG = nil, nil
}

// idle reports whether nothing is held or waiting. Tests use it to check that
// every path gives everything back.
func (a *ingestAdmission) idle() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.slots) != 0 || len(a.principals) != 0 || len(a.tenants) != 0 {
		return false
	}
	if !a.memory.sem.TryAcquire(a.memory.size) {
		return false
	}
	a.memory.sem.Release(a.memory.size)
	return true
}

// waitUntil runs acquire under a context that ends at deadline. It returns
// errIngestBusy when the deadline passes first, and ctx's own error when the
// client went away.
func waitUntil(ctx context.Context, deadline time.Time, acquire func(context.Context) error) error {
	waitCtx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := acquire(waitCtx); err != nil {
		if ctx.Err() == nil {
			return errIngestBusy
		}
		return ctx.Err()
	}
	return nil
}

// ingestDeadlines moves the connection's deadlines for one ingest, replacing
// the server-wide ReadTimeout and WriteTimeout for this request only. Writers
// that cannot set deadlines (some test doubles, wrapped writers) keep the
// server defaults.
type ingestDeadlines struct {
	// body is how long the caller has to send the whole body. It restarts
	// when the caller leaves its queue, so waiting does not eat into it.
	body time.Duration
	// window is how long the ingest may run once it has the body, plus
	// writeSlack for the response.
	window, writeSlack time.Duration
}

func (d ingestDeadlines) armBody(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	now := time.Now()
	_ = rc.SetReadDeadline(now.Add(d.body))
	_ = rc.SetWriteDeadline(now.Add(d.body + d.window + d.writeSlack))
}

func (d ingestDeadlines) armProcessing(w http.ResponseWriter) {
	rc := http.NewResponseController(w)
	_ = rc.SetWriteDeadline(time.Now().Add(d.window + d.writeSlack))
}

// respondIngestBusy answers 503 with a Retry-After a little past the queue wait.
func respondIngestBusy(w http.ResponseWriter, queueWait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(queueWait/time.Second)+1))
	respondError(w, http.StatusServiceUnavailable, "ingest_busy", "too many ingests in progress, retry shortly")
}

// errIngestBusy means the memory budget stayed taken for the whole queue wait.
var errIngestBusy = errors.New("ingest memory budget is busy")

// ingestMemory is the admission control for ingest memory. The concurrency
// slots count ingests, but one ingest of a 25 MiB report holds far more memory
// than eight of 100 KiB, so each ingest also charges 64 bytes per byte of its
// report against one weighted budget before the report is decoded. A charge
// bigger than the whole budget is capped to it, so a big report runs alone
// instead of waiting forever. Waiting is bounded by the same queue wait as the
// concurrency slots.
type ingestMemory struct {
	sem       *semaphore.Weighted
	size      int64
	queueWait time.Duration
}

// newIngestMemory makes a budget of size bytes; zero or less means the default.
func newIngestMemory(size int64, queueWait time.Duration) *ingestMemory {
	if size <= 0 {
		size = DefaultIngestMemoryBudget
	}
	return &ingestMemory{sem: semaphore.NewWeighted(size), size: size, queueWait: queueWait}
}

// charge is the weight of an ingest whose report is rawBytes long: at least one
// unit, at most the whole budget.
func (m *ingestMemory) charge(rawBytes int) int64 {
	return min(max(int64(rawBytes), 1)*ingestBytesPerRawByte, m.size)
}

// acquire waits for the charge of a rawBytes-long report and returns the
// function that gives it back, which is safe to call more than once. It
// returns errIngestBusy when the budget stays taken for the queue wait, and
// the context's error when ctx ends first (the client went away). A nil budget
// admits everything.
func (m *ingestMemory) acquire(ctx context.Context, rawBytes int) (func(), error) {
	if m == nil {
		return func() {}, nil
	}
	return m.acquireUntil(ctx, time.Now().Add(m.queueWait), rawBytes)
}

// acquireUntil is acquire with a fixed deadline, so a caller that already
// spent part of its wait on something else does not get a fresh one.
func (m *ingestMemory) acquireUntil(ctx context.Context, deadline time.Time, rawBytes int) (func(), error) {
	if m == nil {
		return func() {}, nil
	}
	n := m.charge(rawBytes)
	if err := waitUntil(ctx, deadline, func(ctx context.Context) error { return m.sem.Acquire(ctx, n) }); err != nil {
		return nil, err
	}
	var once sync.Once
	return func() { once.Do(func() { m.sem.Release(n) }) }, nil
}

// detachedContext returns a context that keeps ctx's values and its deadline
// but not its cancellation. The ingest write phase runs on it: a client that
// hangs up cancels the request context, and a write phase cut in half leaves a
// report in processing and findings with no occurrence. The deadline stays, so
// the server still bounds how long a hung-up client's ingest may run.
func detachedContext(ctx context.Context) (context.Context, context.CancelFunc) {
	detached := context.WithoutCancel(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(detached, deadline)
	}
	return detached, func() {}
}

// fallbackIngestAdmission serves handlers built without NewHandler, which have
// no admission control of their own.
var fallbackIngestAdmission = newIngestAdmission(0, 0, defaultIngestQueueWait)

// ingestAdmission returns the handler's admission control.
func (h *Handler) ingestAdmission() *ingestAdmission {
	if h.ingest == nil {
		return fallbackIngestAdmission
	}
	return h.ingest
}
