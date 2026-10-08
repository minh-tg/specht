package server

import (
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5/middleware"
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
	// ingestQueueWait is how long a request waits for a free ingest slot
	// before being told to retry.
	ingestQueueWait = 15 * time.Second
	// DefaultIngestConcurrency is the number of ingests processed at once
	// when RouterConfig.IngestConcurrency is unset.
	DefaultIngestConcurrency = 8
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
	retryAfter := strconv.Itoa(int(queueWait/time.Second) + 1)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			timer := time.NewTimer(queueWait)
			defer timer.Stop()
			select {
			case slots <- struct{}{}:
				defer func() { <-slots }()
			case <-timer.C:
				w.Header().Set("Retry-After", retryAfter)
				respondError(w, http.StatusServiceUnavailable, "ingest_busy", "too many ingests in progress, retry shortly")
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
