package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deadlineRecorder is a ResponseWriter that, like the real connection
// writer, accepts per-request read and write deadlines.
type deadlineRecorder struct {
	*httptest.ResponseRecorder
	mu    sync.Mutex
	read  time.Time
	write time.Time
}

func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.read = t
	return nil
}

func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.write = t
	return nil
}

func TestIngestLimits_ExtendsTheDeadlinesForTheRequest(t *testing.T) {
	gate := ingestLimits(2, time.Second, time.Minute, 10*time.Second)
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	before := time.Now()

	gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})).
		ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/reports", nil))

	assert.WithinDuration(t, before.Add(time.Minute), w.read, 2*time.Second, "an upload may take the full window")
	assert.WithinDuration(t, before.Add(70*time.Second), w.write, 2*time.Second, "the response is written after the upload window")
}

func TestIngestLimits_WorksWhenTheWriterCannotSetDeadlines(t *testing.T) {
	gate := ingestLimits(1, time.Second, time.Minute, time.Second)
	w := httptest.NewRecorder() // no deadline support

	gate(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusNoContent) })).
		ServeHTTP(w, httptest.NewRequest("POST", "/api/v1/reports", nil))

	assert.Equal(t, http.StatusNoContent, w.Code, "missing deadline support must not break ingest")
}

func TestIngestLimits_LimitsConcurrencyAndShedsTheRest(t *testing.T) {
	gate := ingestLimits(1, 30*time.Millisecond, time.Minute, time.Second)
	release := make(chan struct{})
	entered := make(chan struct{})
	slow := gate(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		close(entered)
		<-release
		rw.WriteHeader(http.StatusAccepted)
	}))

	first := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		slow.ServeHTTP(first, httptest.NewRequest("POST", "/api/v1/reports", nil))
		close(done)
	}()
	<-entered

	second := httptest.NewRecorder()
	slow.ServeHTTP(second, httptest.NewRequest("POST", "/api/v1/reports", nil))

	requireAPIError(t, second, http.StatusServiceUnavailable, "ingest_busy")
	assert.NotEmpty(t, second.Header().Get("Retry-After"), "clients are told when to come back")

	close(release)
	<-done
	assert.Equal(t, http.StatusAccepted, first.Code, "the request that held the slot completes normally")
}

func TestIngestLimits_ReleasesTheSlotAfterEachRequest(t *testing.T) {
	gate := ingestLimits(1, 20*time.Millisecond, time.Minute, time.Second)
	ok := gate(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { rw.WriteHeader(http.StatusOK) }))
	panics := gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { panic("boom") }))

	require.Panics(t, func() {
		panics.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil))
	})
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		ok.ServeHTTP(w, httptest.NewRequest("POST", "/", nil))
		require.Equal(t, http.StatusOK, w.Code, "request %d: a finished or panicked request frees its slot", i)
	}
}

func TestIngestLimits_AbandonedWaitDoesNotRunTheHandler(t *testing.T) {
	gate := ingestLimits(1, time.Minute, time.Minute, time.Second)
	hold := make(chan struct{})
	entered := make(chan struct{})
	var runs int
	var mu sync.Mutex
	h := gate(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mu.Lock()
		runs++
		mu.Unlock()
		select {
		case entered <- struct{}{}:
		default:
		}
		<-hold
	}))
	go h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil))
	<-entered

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil).WithContext(ctx))
	close(hold)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 1, runs, "a client that gave up while queued must not start an ingest")
}

func TestRequestTimeout_IngestGetsALongerBudgetThanOtherRoutes(t *testing.T) {
	mw := requestTimeout(30*time.Millisecond, 600*time.Millisecond)
	slowHandler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			w.WriteHeader(http.StatusGatewayTimeout)
		case <-time.After(150 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		}
	}))

	other := httptest.NewRecorder()
	slowHandler.ServeHTTP(other, httptest.NewRequest("GET", "/api/v1/projects", nil))
	assert.Equal(t, http.StatusGatewayTimeout, other.Code, "ordinary routes keep the short timeout")

	ingest := httptest.NewRecorder()
	slowHandler.ServeHTTP(ingest, httptest.NewRequest("POST", "/api/v1/reports", nil))
	assert.Equal(t, http.StatusOK, ingest.Code, "ingest may run past the ordinary timeout")

	wrongMethod := httptest.NewRecorder()
	slowHandler.ServeHTTP(wrongMethod, httptest.NewRequest("GET", "/api/v1/reports", nil))
	assert.Equal(t, http.StatusGatewayTimeout, wrongMethod.Code, "only the ingest call is extended, not report reads")
}
