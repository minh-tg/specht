package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

// acquireWithin reports whether the charge for rawBytes is granted within d.
func acquireWithin(m *ingestMemory, rawBytes int, d time.Duration) (release func(), ok bool) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	rel, err := m.acquire(ctx, rawBytes)
	if err != nil {
		return nil, false
	}
	return rel, true
}

func TestIngestMemory_ChargesSixtyFourTimesTheRawBytes(t *testing.T) {
	m := newIngestMemory(1<<20, time.Second)
	assert.EqualValues(t, 64*1000, m.charge(1000))
	assert.EqualValues(t, 64, m.charge(1))
	assert.EqualValues(t, 64, m.charge(0), "an empty document still takes a charge, so the budget is never bypassed")
}

func TestIngestMemory_ACharge_PastTheBudgetIsCappedSoTheDocumentRunsAlone(t *testing.T) {
	m := newIngestMemory(6400, time.Second)
	assert.EqualValues(t, 6400, m.charge(10_000_000))

	release, ok := acquireWithin(m, 10_000_000, time.Second)
	require.True(t, ok, "one big document must be admitted when nothing else runs")
	_, ok = acquireWithin(m, 1, 30*time.Millisecond)
	assert.False(t, ok, "nothing runs next to a document that took the whole budget")
	release()
	_, ok = acquireWithin(m, 1, time.Second)
	assert.True(t, ok)
}

func TestIngestMemory_ManySmallIngestsRunTogether(t *testing.T) {
	m := newIngestMemory(64*1000, time.Second) // room for 1000 raw bytes
	var releases []func()
	for i := range 50 {
		rel, ok := acquireWithin(m, 10, 100*time.Millisecond) // 50 x 10 bytes
		require.True(t, ok, "ingest %d", i)
		releases = append(releases, rel)
	}
	for _, rel := range releases {
		rel()
	}
}

func TestIngestMemory_TwoNearBudgetIngestsRunOneAfterTheOther(t *testing.T) {
	m := newIngestMemory(64*1000, time.Second)
	first, ok := acquireWithin(m, 700, time.Second)
	require.True(t, ok)

	got := make(chan func(), 1)
	go func() {
		rel, _ := acquireWithin(m, 700, 2*time.Second)
		got <- rel
	}()
	select {
	case <-got:
		t.Fatal("the second near-budget ingest was admitted while the first still held its charge")
	case <-time.After(50 * time.Millisecond):
	}
	first()
	select {
	case rel := <-got:
		require.NotNil(t, rel, "the second ingest is admitted once the first releases")
		rel()
	case <-time.After(2 * time.Second):
		t.Fatal("the second ingest was never admitted")
	}
}

func TestIngestMemory_AWaitThatTimesOutIsBusy(t *testing.T) {
	m := newIngestMemory(6400, 20*time.Millisecond)
	hold, ok := acquireWithin(m, 100, time.Second)
	require.True(t, ok)
	defer hold()

	_, err := m.acquire(context.Background(), 100)
	require.ErrorIs(t, err, errIngestBusy)
}

func TestIngestMemory_ACancelledWaitIsNotBusyAndLeaksNothing(t *testing.T) {
	m := newIngestMemory(6400, time.Minute)
	hold, ok := acquireWithin(m, 100, time.Second)
	require.True(t, ok)

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { _, err := m.acquire(ctx, 100); errc <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	err := <-errc
	require.ErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, errIngestBusy, "a client that hung up is not a busy answer")

	hold()
	_, ok = acquireWithin(m, 100, time.Second)
	assert.True(t, ok, "the cancelled waiter must not keep part of the budget")
}

func TestIngestMemory_ReleaseIsIdempotent(t *testing.T) {
	m := newIngestMemory(6400, time.Second)
	rel, ok := acquireWithin(m, 100, time.Second)
	require.True(t, ok)
	rel()
	rel()                                           // a second release must not hand out budget that is not there
	whole, ok := acquireWithin(m, 100, time.Second) // charges the whole 6400
	require.True(t, ok)
	defer whole()
	_, ok = acquireWithin(m, 1, 30*time.Millisecond)
	assert.False(t, ok, "two releases must not have grown the budget past its size")
}

func TestIngestMemory_ANilBudgetAdmitsEverything(t *testing.T) {
	var m *ingestMemory
	rel, err := m.acquire(context.Background(), 1<<30)
	require.NoError(t, err)
	rel()
}

// ingestRoute sends an ingest whose raw_data is rawLen bytes through the real
// router and reports the response.
func ingestRoute(t *testing.T, router http.Handler, ctx context.Context, rawLen int) *httptest.ResponseRecorder {
	t.Helper()
	return ingestRouteAs(t, router, ctx, rawLen, testToken(t))
}

// ingestRouteAs is ingestRoute for the caller that token stands for.
func ingestRouteAs(t *testing.T, router http.Handler, ctx context.Context, rawLen int, token string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/api/v1/reports", ingestBody(rawLen)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// userToken is a session token for the admin user with the given id, so tests
// can tell callers apart.
func userToken(t *testing.T, id string) string {
	t.Helper()
	a, err := auth.NewJWTAuthenticator(testJWTSecret)
	require.NoError(t, err)
	tok, err := a.CreateToken(id, id+"@example.com", auth.RoleAdmin, 0)
	require.NoError(t, err)
	return tok
}

// The budget is mounted on the real route: while one ingest holds the whole
// budget, the next one waits the queue time and is told to retry, and the
// use case never sees it.
func TestIngestRoute_AnswersBusyWhenTheMemoryBudgetStaysTaken(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 4)
	var runs atomic.Int32
	mock := &mockUsecases{
		ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			runs.Add(1)
			entered <- struct{}{}
			select {
			case <-release:
			case <-time.After(5 * time.Second):
			}
			return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
		},
	}
	// 6400 bytes of budget; a 100-byte document charges all of it.
	router := NewRouter(RouterConfig{
		Usecases: mock, JWTAuth: testJWTAuth, IngestConcurrency: 4,
		IngestMemoryBudget: 6400, IngestQueueWait: 40 * time.Millisecond,
	})
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- ingestRoute(t, router, context.Background(), 100) }()
	<-entered

	w := ingestRoute(t, router, context.Background(), 100)
	requireAPIError(t, w, http.StatusServiceUnavailable, "ingest_busy")
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
	assert.EqualValues(t, 1, runs.Load(), "a refused ingest never reaches the use case")

	close(release)
	first := <-done
	assert.Equal(t, http.StatusCreated, first.Code)
}

func TestIngestRoute_ManySmallIngestsShareTheBudget(t *testing.T) {
	release := make(chan struct{})
	var inFlight, peak atomic.Int32
	mock := &mockUsecases{
		ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			n := inFlight.Add(1)
			for {
				p := peak.Load()
				if n <= p || peak.CompareAndSwap(p, n) {
					break
				}
			}
			select {
			case <-release:
			case <-time.After(5 * time.Second):
			}
			inFlight.Add(-1)
			return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
		},
	}
	router := NewRouter(RouterConfig{
		// 16 slots, so the one project the eight callers share may hold eight.
		Usecases: mock, JWTAuth: testJWTAuth, IngestConcurrency: 16,
		IngestMemoryBudget: 64 * 100_000, IngestQueueWait: time.Second,
	})
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := ingestRouteAs(t, router, context.Background(), 100, userToken(t, fmt.Sprintf("caller-%d", i)))
			assert.Equal(t, http.StatusCreated, w.Code)
		}()
	}
	require.Eventually(t, func() bool { return inFlight.Load() == 8 }, 2*time.Second, 5*time.Millisecond,
		"eight small ingests fit in the budget together")
	close(release)
	wg.Wait()
}

// Every way an ingest can end frees its charge: a normal answer, an error from
// the use case, and a client that hung up while the ingest ran.
func TestIngestRoute_ReleasesTheChargeOnEveryPath(t *testing.T) {
	var mode atomic.Value
	mode.Store("ok")
	mock := &mockUsecases{
		ingestReportFn: func(ctx context.Context, _ usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			switch mode.Load() {
			case "error":
				return nil, assert.AnError
			case "hangup":
				<-ctx.Done()
				return nil, ctx.Err()
			}
			return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
		},
	}
	router := NewRouter(RouterConfig{
		Usecases: mock, JWTAuth: testJWTAuth, IngestConcurrency: 4,
		IngestMemoryBudget: 6400, IngestQueueWait: 100 * time.Millisecond,
	})
	for _, m := range []string{"error", "hangup", "ok", "error", "ok"} {
		mode.Store(m)
		ctx := context.Background()
		if m == "hangup" {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, 30*time.Millisecond)
			defer cancel()
		}
		ingestRoute(t, router, ctx, 100)
		// Each ingest charges the whole budget, so the next one only gets in
		// if the last one gave its charge back.
		mode.Store("ok")
		w := ingestRoute(t, router, context.Background(), 100)
		require.Equal(t, http.StatusCreated, w.Code, "after the %q ingest the budget must be free again", m)
	}
}

func TestIngestRoute_ARefusedClientDoesNotWaitForTheBudgetPastItsOwnTimeout(t *testing.T) {
	hold := make(chan struct{})
	entered := make(chan struct{}, 4)
	mock := &mockUsecases{
		ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			entered <- struct{}{}
			select {
			case <-hold:
			case <-time.After(2 * time.Second): // a missing budget must fail the test, not hang it
			}
			return &usecase.IngestReportOutput{ReportID: "r"}, nil
		},
	}
	router := NewRouter(RouterConfig{
		Usecases: mock, JWTAuth: testJWTAuth, IngestConcurrency: 4,
		IngestMemoryBudget: 6400, IngestQueueWait: time.Minute,
	})
	go ingestRoute(t, router, context.Background(), 100)
	<-entered
	defer close(hold)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	start := time.Now()
	w := ingestRoute(t, router, ctx, 100)
	assert.Less(t, time.Since(start), 5*time.Second)
	assert.NotEqual(t, http.StatusCreated, w.Code)
	assert.False(t, strings.Contains(w.Body.String(), "rep-1"))
}

// A panic in the use case unwinds through the handler, and the charge goes
// back with it.
func TestIngestReport_ReleasesTheChargeWhenTheUseCasePanics(t *testing.T) {
	mock := &mockUsecases{
		ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			panic("boom")
		},
	}
	h := NewHandler(mock)
	h.ingest = newIngestAdmission(4, 6400, 20*time.Millisecond)
	req := httptest.NewRequest("POST", "/api/v1/reports", ingestBody(100))
	req.Header.Set("Content-Type", "application/json")
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "u-admin", Role: auth.RoleAdmin}))

	require.Panics(t, func() { h.IngestReport(httptest.NewRecorder(), req) })

	rel, ok := acquireWithin(h.ingest.memory, 100, time.Second)
	require.True(t, ok, "the panicked ingest must give its whole charge back")
	rel()
	assert.True(t, h.ingest.idle(), "and every slot and gate with it")
}
