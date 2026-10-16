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
	// ingestWindow is how long one ingest may take, upload included. The
	// 25 MiB body cap needs about 1 MiB/s to fit in 30 s, which a CI runner on
	// a slow link does not always manage.
	ingestWindow = 2 * time.Minute
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

// ingestLimits guards the ingest endpoint. A request first takes one of
// concurrency slots, so a leaked ingest key cannot pile up parses that each
// hold many times the request body in memory; it waits up to queueWait and
// then gets a 503 with Retry-After. Once it has a slot the connection's read
// and write deadlines are moved out to window (plus slack for the response),
// replacing the server-wide ReadTimeout for this request only.
func ingestLimits(concurrency int, queueWait, window, writeSlack time.Duration) func(http.Handler) http.Handler {
	if concurrency < 1 {
		concurrency = DefaultIngestConcurrency
	}
	slots := make(chan struct{}, concurrency)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			timer := time.NewTimer(queueWait)
			defer timer.Stop()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-timer.C:
				respondIngestBusy(w, queueWait)
				return
			case <-r.Context().Done():
				return
			}
			// Writers that cannot set deadlines (some test doubles, wrapped
			// writers) keep the server defaults.
			rc := http.NewResponseController(w)
			deadline := time.Now().Add(window)
			_ = rc.SetReadDeadline(deadline)
			_ = rc.SetWriteDeadline(deadline.Add(writeSlack))
			next.ServeHTTP(w, r)
		})
	}
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
	n := m.charge(rawBytes)
	waitCtx, cancel := context.WithTimeout(ctx, m.queueWait)
	defer cancel()
	if err := m.sem.Acquire(waitCtx, n); err != nil {
		if ctx.Err() == nil {
			return nil, errIngestBusy
		}
		return nil, ctx.Err()
	}
	var once sync.Once
	return func() { once.Do(func() { m.sem.Release(n) }) }, nil
}
