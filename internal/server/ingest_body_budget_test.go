package server

import (
	"context"
	"fmt"
	"io"
	"net"
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
// N distinct ingest keys of one project ("my-app"), "other-N" bearers to
// keys of a second project ("other-app") and "third-N" to a third ("third-app"). bytesRead counts the body bytes the
// handler consumed, across requests.
func ingestPrincipalServer(t *testing.T, adm *ingestAdmission, mock *mockUsecases, bytesRead *atomic.Int64) *httptest.Server {
	t.Helper()
	mock.isProjectMemberFn = func(context.Context, string, string) (bool, error) { return false, nil }
	mock.getProjectFn = func(_ context.Context, slug string) (*usecase.ProjectResponse, error) {
		if slug == "other-app" {
			return &usecase.ProjectResponse{ID: otherProjectID, Slug: slug}, nil
		}
		if slug == "third-app" {
			return &usecase.ProjectResponse{ID: thirdProjectID, Slug: slug}, nil
		}
		return &usecase.ProjectResponse{ID: fairnessProjectID, Slug: slug}, nil
	}
	h := NewHandler(mock)
	h.ingest = adm
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		projectID := fairnessProjectID
		if strings.HasPrefix(token, "other-") {
			projectID = otherProjectID
		}
		if strings.HasPrefix(token, "third-") {
			projectID = thirdProjectID
		}
		ident := &auth.Identity{UserID: "creator", ProjectID: projectID, KeyHash: "hash-" + token, IsAPIKey: true, Scopes: []string{auth.ScopeIngest}}
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

const (
	otherProjectID = "00000000-0000-0000-0000-000000000002"
	thirdProjectID = "00000000-0000-0000-0000-000000000003"
)

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

// A body without a declared length reserves a chunk ahead of what it has sent,
// so it is refused unread while the budget is full too.
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

// While the body is read an ingest holds one byte of budget per byte; the
// charge for decoding is taken only once the whole body is in memory.
func TestIngestTicket_ReserveHoldsRawBytesAndChargeRaisesToTheFullCharge(t *testing.T) {
	a := newIngestAdmission(8, 64*1000, 20*time.Millisecond)
	tk, err := a.enter(context.Background(), "p1", "t1")
	require.NoError(t, err)
	require.NoError(t, tk.reserve(context.Background(), 1000))
	assert.EqualValues(t, 1000, tk.held.global, "one byte of budget per body byte")

	require.NoError(t, tk.reserve(context.Background(), 500))
	assert.EqualValues(t, 1000, tk.held.global, "asking for less holds what was held")

	require.NoError(t, tk.charge(context.Background(), 1000))
	assert.EqualValues(t, 64*1000, tk.held.global, "the full decoding charge")

	tk.release()
	assert.True(t, a.idle(), "the hold is given back in full")
}

// An upgrade the budget cannot give ends in errIngestBusy after one queue wait
// and the raw hold is given back with the ticket, so a request never keeps
// others waiting on what it holds for longer than that.
func TestIngestTicket_ChargeThatDoesNotFitFailsAndReleasesTheRawHold(t *testing.T) {
	a := newIngestAdmission(8, 64*1000, 50*time.Millisecond)
	holder, err := a.enter(context.Background(), "p1", "t1")
	require.NoError(t, err)
	require.NoError(t, holder.charge(context.Background(), 900), "takes most of the budget")

	waiter, err := a.enter(context.Background(), "p2", "t2")
	require.NoError(t, err)
	require.NoError(t, waiter.reserve(context.Background(), 800), "the raw bytes fit")
	start := time.Now()
	require.ErrorIs(t, waiter.charge(context.Background(), 800), errIngestBusy)
	assert.GreaterOrEqual(t, time.Since(start), 40*time.Millisecond, "waited the queue wait")
	waiter.release()

	holder.release()
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

// postBody posts a report of about size bytes for project, as the given key.
func postBody(t *testing.T, srv *httptest.Server, key, project string, size int) int {
	t.Helper()
	body := `{"project":"` + project + `","scanner":"trivy","raw_data":"` + strings.Repeat("z", size) + `"}`
	status, _, _ := postIngest(t, srv, key, body)
	return status
}

// stallAfterHead opens a request that has sent only the head of its body, and keeps
// the connection open. Declared 0 or less means chunked.
func stallAfterHead(t *testing.T, srv *httptest.Server, key, project string, declared int) {
	t.Helper()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	head := `{"project":"` + project + `","scanner":"trivy","raw_data":"`
	framing, start := "Transfer-Encoding: chunked\r\n", fmt.Sprintf("%x\r\n%s\r\n", len(head), head)
	if declared > 0 {
		framing, start = fmt.Sprintf("Content-Length: %d\r\n", declared), head
	}
	_, err = fmt.Fprintf(conn, "POST /api/v1/reports HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s\r\nContent-Type: application/json\r\n%s\r\n%s", key, framing, start)
	require.NoError(t, err)
	time.Sleep(200 * time.Millisecond) // the handler has read the head and is waiting for the rest
}

// One chunked uploader that stops after the head of its body holds only what
// it has sent, so other projects' uploads that fit the budget still run.
func TestIngestReport_SlowChunkedUploaderDoesNotBlockOtherTenants(t *testing.T) {
	adm := newIngestAdmission(8, 0, 300*time.Millisecond)
	var bytesRead atomic.Int64
	srv := ingestPrincipalServer(t, adm, okIngest(), &bytesRead)
	stallAfterHead(t, srv, "key-1", "my-app", 0)

	assert.Equal(t, http.StatusCreated, postBody(t, srv, "other-1", "other-app", 10<<20), "10 MiB")
	assert.Equal(t, http.StatusCreated, postBody(t, srv, "other-2", "other-app", 7<<20), "7 MiB")
	assert.Equal(t, http.StatusCreated, postBody(t, srv, "other-3", "other-app", 1<<20), "1 MiB")
}

// The same for an uploader that declares the largest body and then stalls: it
// holds 25 MiB of budget, not the 1.6 GiB charge for decoding it.
func TestIngestReport_SlowLargeUploaderDoesNotBlockAnotherLargeUpload(t *testing.T) {
	adm := newIngestAdmission(8, 0, 300*time.Millisecond)
	var bytesRead atomic.Int64
	srv := ingestPrincipalServer(t, adm, okIngest(), &bytesRead)
	stallAfterHead(t, srv, "key-1", "my-app", maxIngestBodyBytes)

	assert.Equal(t, http.StatusCreated, postBody(t, srv, "other-1", "other-app", maxIngestBodyBytes-200), "another tenant's 25 MiB")
}

// Two uploads that cannot both get the decoding charge do not wait on each
// other for good: the one that does not fit is refused after one queue wait,
// gives back what it held, and nothing stays reserved.
func TestIngestReport_UploadsThatCannotBothBeChargedDoNotDeadlock(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 2)
	adm := newIngestAdmission(8, 64*1000, 200*time.Millisecond)
	var bytesRead atomic.Int64
	srv := ingestPrincipalServer(t, adm, blockingMock(entered, release), &bytesRead)

	first := make(chan int, 1)
	go func() { first <- postBody(t, srv, "key-1", "my-app", 700) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first upload never reached the use case")
	}

	start := time.Now()
	assert.Equal(t, http.StatusServiceUnavailable, postBody(t, srv, "other-1", "other-app", 700), "the second does not fit next to the first")
	assert.Less(t, time.Since(start), 3*time.Second)

	close(release)
	assert.Equal(t, http.StatusCreated, <-first)
	assert.Eventually(t, adm.idle, time.Second, 5*time.Millisecond, "nothing stays reserved")
}

// stallDeclaredUploads opens count connections for project, spread over the
// keys named prefix-0 ... prefix-(keys-1), each declaring the largest body and
// sending only the head.
func stallDeclaredUploads(t *testing.T, srv *httptest.Server, prefix, project string, keys, count int) {
	t.Helper()
	head := `{"project":"` + project + `","scanner":"trivy","raw_data":"`
	for i := 0; i < count; i++ {
		conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
		require.NoError(t, err)
		t.Cleanup(func() { _ = conn.Close() })
		_, err = fmt.Fprintf(conn, "POST /api/v1/reports HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer %s-%d\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
			prefix, i%keys, maxIngestBodyBytes, head)
		require.NoError(t, err)
	}
	time.Sleep(500 * time.Millisecond) // every handler has read its head and is waiting for the rest
}

// A declared Content-Length is a claim, not a payment: 40 stalled uploads that
// each declare 25 MiB from one project hold a chunk each, so another project's
// large report still gets in.
func TestIngestReport_StalledDeclaredUploadsOfOneTenantDoNotBlockAnother(t *testing.T) {
	adm := newIngestAdmission(8, 0, 300*time.Millisecond)
	var bytesRead atomic.Int64
	srv := ingestPrincipalServer(t, adm, okIngest(), &bytesRead)
	stallDeclaredUploads(t, srv, "key", "my-app", 10, 40)

	assert.Equal(t, http.StatusCreated, postBody(t, srv, "other-1", "other-app", 17<<20), "17 MiB")
	assert.Equal(t, http.StatusCreated, postBody(t, srv, "other-2", "other-app", 16<<20), "16 MiB")
}

func TestIngestReport_StalledDeclaredUploadsOfTwoTenantsDoNotBlockAThird(t *testing.T) {
	adm := newIngestAdmission(8, 0, 300*time.Millisecond)
	var bytesRead atomic.Int64
	srv := ingestPrincipalServer(t, adm, okIngest(), &bytesRead)
	stallDeclaredUploads(t, srv, "key", "my-app", 10, 40)
	stallDeclaredUploads(t, srv, "other", "other-app", 10, 40)

	assert.Equal(t, http.StatusCreated, postBody(t, srv, "third-1", "third-app", 1<<20), "1 MiB")
}
