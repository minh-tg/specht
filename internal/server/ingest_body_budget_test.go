package server

import (
	"context"
	"fmt"
	"io"
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

// ingestPrincipalServer serves the ingest handler and maps "key-N" bearers to
// N distinct ingest keys of one project. bytesRead counts the body bytes the
// handler consumed, across requests.
func ingestPrincipalServer(t *testing.T, adm *ingestAdmission, mock *mockUsecases, bytesRead *atomic.Int64) *httptest.Server {
	t.Helper()
	mock.isProjectMemberFn = func(context.Context, string, string) (bool, error) { return false, nil }
	mock.getProjectFn = func(_ context.Context, slug string) (*usecase.ProjectResponse, error) {
		return &usecase.ProjectResponse{ID: fairnessProjectID, Slug: slug}, nil
	}
	h := NewHandler(mock)
	h.ingest = adm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		ident := &auth.Identity{UserID: "creator", ProjectID: fairnessProjectID, KeyHash: "hash-" + token, IsAPIKey: true, Scopes: []string{auth.ScopeIngest}}
		cr := &countingReader{r: r.Body}
		r.Body = struct {
			io.Reader
			io.Closer
		}{cr, r.Body}
		defer func() { bytesRead.Add(cr.count()) }()
		h.IngestReport(w, r.WithContext(auth.ContextWithIdentity(r.Context(), ident)))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// blockingMock holds every ingest inside the use case until release closes.
func blockingMock(entered chan<- struct{}, release <-chan struct{}) *mockUsecases {
	return &mockUsecases{ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
		entered <- struct{}{}
		<-release
		return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
	}}
}

// holdWholeBudget starts one ingest that charges the entire budget and waits
// until it is inside the use case.
func holdWholeBudget(t *testing.T, srv *httptest.Server, entered <-chan struct{}) {
	t.Helper()
	go postIngest(t, srv, "key-0", validIngest)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the budget holder never started")
	}
}

// An ingest the budget cannot take is refused before its body is read, so many
// keys posting large bodies at a full budget buffer nothing beyond the head
// each request needs to name its project.
func TestIngestReport_RefusedRequestsDoNotReadTheirBodies(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	// Budget of 64*100 bytes: the first 100-byte document charges all of it.
	adm := newIngestAdmission(8, 6400, 100*time.Millisecond)
	var bytesRead atomic.Int64
	srv := ingestPrincipalServer(t, adm, blockingMock(entered, release), &bytesRead)
	holdWholeBudget(t, srv, entered)
	t.Cleanup(func() { close(release) })
	bytesRead.Store(0)

	const keys, bodySize = 12, 512 << 10
	raw := strings.Repeat("x", bodySize)
	var wg sync.WaitGroup
	statuses := make([]int, keys)
	for i := 0; i < keys; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			body := `{"project":"my-app","scanner":"trivy","raw_data":"` + raw + `"}`
			statuses[i], _, _ = postIngest(t, srv, fmt.Sprintf("key-%d", i+1), body)
		}(i)
	}
	wg.Wait()
	buffered := bytesRead.Load()

	for i, s := range statuses {
		assert.Equal(t, http.StatusServiceUnavailable, s, "key-%d was refused", i+1)
	}
	assert.LessOrEqual(t, buffered, int64(keys*ingestHeadBytes), "refused requests read their head and nothing more")
}

// A body without a declared length reserves the largest allowed body, so it is
// refused unread while the budget is full too.
func TestIngestReport_ChunkedBodyIsReservedBeforeItIsRead(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	adm := newIngestAdmission(8, 6400, 100*time.Millisecond)
	var bytesRead atomic.Int64
	srv := ingestPrincipalServer(t, adm, blockingMock(entered, release), &bytesRead)
	holdWholeBudget(t, srv, entered)
	t.Cleanup(func() { close(release) })
	bytesRead.Store(0)

	raw := strings.Repeat("x", 512<<10)
	body := io.NopCloser(strings.NewReader(`{"project":"my-app","scanner":"trivy","raw_data":"` + raw + `"}`))
	req, err := http.NewRequest(http.MethodPost, srv.URL, body)
	require.NoError(t, err)
	req.ContentLength = -1 // unknown length: sent chunked
	req.Header.Set("Authorization", "Bearer key-1")
	resp, err := srv.Client().Do(req)
	require.NoError(t, err)
	_ = resp.Body.Close()

	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	assert.LessOrEqual(t, bytesRead.Load(), int64(ingestHeadBytes))
}

// Everything an ingest reserves is given back whichever way it ends.
func TestIngestReport_GivesBackTheReservationOnEveryPath(t *testing.T) {
	adm := newIngestAdmission(8, 0, 100*time.Millisecond)
	var bytesRead atomic.Int64
	srv := ingestPrincipalServer(t, adm, okIngest(), &bytesRead)

	status, _, _ := postIngest(t, srv, "key-1", validIngest)
	assert.Equal(t, http.StatusCreated, status)
	status, _, _ = postIngest(t, srv, "key-1", `{"project":"my-app","scanner":"trivy"`)
	assert.Equal(t, http.StatusBadRequest, status, "truncated document")
	status, _, _ = postIngest(t, srv, "key-1", `{"project":"my-app","raw_data":{"a":1}}`)
	assert.Equal(t, http.StatusBadRequest, status, "missing scanner")

	assert.Eventually(t, adm.idle, time.Second, 5*time.Millisecond, "nothing stays reserved")
}

// A reservation made for the largest body shrinks to the bytes that arrived,
// so a short chunked upload does not keep the budget from the next ingest.
func TestIngestTicket_ShrinkGivesBackWhatTheBodyDidNotNeed(t *testing.T) {
	a := newIngestAdmission(2, 64*1000, 20*time.Millisecond)
	first, err := a.enter(context.Background(), "p1", "t1")
	require.NoError(t, err)
	require.NoError(t, first.reserve(context.Background(), 1000), "reserves the whole budget")

	second, err := a.enter(context.Background(), "p2", "t2")
	require.NoError(t, err)
	require.ErrorIs(t, second.reserve(context.Background(), 800), errIngestBusy, "no room next to the full reservation")
	second.release()

	first.shrink(100)
	third, err := a.enter(context.Background(), "p3", "t3")
	require.NoError(t, err)
	require.NoError(t, third.reserve(context.Background(), 800), "the part the first body did not need is free")

	third.release()
	first.release()
	assert.True(t, a.idle())
}

// A request the memory cannot take holds neither a global slot nor a project
// place, so it cannot starve ingests that fit.
func TestIngestTicket_RefusedReservationHoldsNoSlot(t *testing.T) {
	a := newIngestAdmission(2, 64*100, 20*time.Millisecond)
	hold, err := a.enter(context.Background(), "p1", "t1")
	require.NoError(t, err)
	require.NoError(t, admitTicket(hold, context.Background(), 100))

	blocked, err := a.enter(context.Background(), "p2", "t2")
	require.NoError(t, err)
	require.ErrorIs(t, blocked.reserve(context.Background(), 100), errIngestBusy)
	assert.Equal(t, 1, len(a.slots), "only the holder has a slot")
	blocked.release()
	hold.release()
	assert.True(t, a.idle())
}
