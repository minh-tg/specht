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

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/client"
	"github.com/minh-tg/specht/internal/usecase"
)

// The adapter and the CLI must wait out a full-length upload, a queued slot
// included, or a slow but successful ingest fails on the client side.
func TestClientIngestTimeoutOutlastsTheServerWindow(t *testing.T) {
	serverWindow := ingestBodyWindow + ingestWindow + ingestWriteSlack + defaultIngestQueueWait
	assert.Greater(t, client.IngestRequestTimeout, serverWindow)
}

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

func TestIngestDeadlines_BodyWindowThenProcessingWindow(t *testing.T) {
	d := ingestDeadlines{body: 30 * time.Second, window: time.Minute, writeSlack: 10 * time.Second}
	w := &deadlineRecorder{ResponseRecorder: httptest.NewRecorder()}
	before := time.Now()

	d.armBody(w)
	assert.WithinDuration(t, before.Add(30*time.Second), w.read, 2*time.Second, "the body has its own, shorter window")
	assert.WithinDuration(t, before.Add(100*time.Second), w.write, 2*time.Second, "the response can still be written after upload and processing")

	d.armProcessing(w)
	assert.WithinDuration(t, before.Add(70*time.Second), w.write, 2*time.Second, "processing gets its whole window from the moment it starts")
}

func TestIngestDeadlines_WorkWhenTheWriterCannotSetDeadlines(t *testing.T) {
	d := ingestDeadlines{body: time.Second, window: time.Minute, writeSlack: time.Second}
	w := httptest.NewRecorder() // no deadline support
	assert.NotPanics(t, func() { d.armBody(w); d.armProcessing(w) })
}

func enterAll(t *testing.T, a *ingestAdmission, principal string, n int) []*ingestTicket {
	t.Helper()
	var out []*ingestTicket
	for range n {
		tk, err := a.enter(context.Background(), principal, principal)
		require.NoError(t, err, "%s should get a place", principal)
		out = append(out, tk)
	}
	return out
}

func TestIngestAdmission_ACallerHoldsAtMostHalfTheConcurrency(t *testing.T) {
	a := newIngestAdmission(8, 0, 30*time.Millisecond)
	assert.Equal(t, 4, a.perPrincipal)
	assert.Equal(t, 1, newIngestAdmission(1, 0, time.Second).perPrincipal, "a single slot is still usable")
	assert.Equal(t, 1, newIngestAdmission(2, 0, time.Second).perPrincipal)
	assert.Equal(t, 1, newIngestAdmission(3, 0, time.Second).perPrincipal)

	mine := enterAll(t, a, "key:a", 4)
	_, err := a.enter(context.Background(), "key:a", "key:a")
	require.ErrorIs(t, err, errIngestBusy, "the fifth ingest of one caller waits its turn and is told to retry")

	other, err := a.enter(context.Background(), "key:b", "key:b")
	require.NoError(t, err, "another caller is not delayed by the first")
	other.release()
	for _, tk := range mine {
		tk.release()
	}
	assert.True(t, a.idle())
}

func TestIngestAdmission_ACallerWaitingInItsOwnQueueDoesNotBlockOthers(t *testing.T) {
	a := newIngestAdmission(2, 0, time.Minute) // one place each
	first, err := a.enter(context.Background(), "user:a", "user:a")
	require.NoError(t, err)

	waiter := make(chan error, 1)
	go func() {
		_, err := a.enter(context.Background(), "user:a", "user:a")
		waiter <- err
	}()
	time.Sleep(20 * time.Millisecond)

	start := time.Now()
	other, err := a.enter(context.Background(), "user:b", "user:b")
	require.NoError(t, err)
	assert.Less(t, time.Since(start), time.Second)
	require.NoError(t, admitTicket(other, context.Background(), 10), "and takes a global slot while the first caller's second ingest waits")
	other.release()

	first.release()
	require.NoError(t, <-waiter, "the waiting ingest gets the place when the first leaves")
}

func TestIngestAdmission_TheGlobalSlotIsTakenOnlyAfterTheBody(t *testing.T) {
	a := newIngestAdmission(2, 0, 30*time.Millisecond) // two global slots, one place per caller
	// Two callers fill every global slot.
	var admitted []*ingestTicket
	for _, p := range []string{"user:a", "user:b"} {
		tk, err := a.enter(context.Background(), p, p)
		require.NoError(t, err)
		require.NoError(t, admitTicket(tk, context.Background(), 10))
		admitted = append(admitted, tk)
	}
	// A third caller can still enter and read its body: that holds no slot.
	third, err := a.enter(context.Background(), "user:c", "user:c")
	require.NoError(t, err, "reading a body does not need a global slot")
	// It waits for a slot only when its body is in.
	require.ErrorIs(t, admitTicket(third, context.Background(), 10), errIngestBusy)
	third.release()

	admitted[0].release()
	again, err := a.enter(context.Background(), "user:c", "user:c")
	require.NoError(t, err)
	require.NoError(t, admitTicket(again, context.Background(), 10), "a freed slot goes to the next caller")
	again.release()
	admitted[1].release()
	assert.True(t, a.idle())
}

func TestIngestAdmission_ACallerGetsAProportionalShareOfTheMemory(t *testing.T) {
	a := newIngestAdmission(8, 64*8000, time.Second) // budget for 8000 raw bytes
	assert.EqualValues(t, 64*4000, a.memoryShare, "half the budget for half the slots")

	big, err := a.enter(context.Background(), "user:a", "user:a")
	require.NoError(t, err)
	require.NoError(t, admitTicket(big, context.Background(), 4000), "one caller may use its whole share")

	more, err := a.enter(context.Background(), "user:a", "user:a")
	require.NoError(t, err)
	short := newIngestAdmission(8, 64*8000, 30*time.Millisecond)
	_ = short
	waitCtx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	assert.Error(t, admitTicket(more, waitCtx, 100), "the same caller cannot exceed its share")
	more.release()

	rival, err := a.enter(context.Background(), "user:b", "user:b")
	require.NoError(t, err)
	require.NoError(t, admitTicket(rival, context.Background(), 3000), "another caller still has its own share of the budget")
	rival.release()
	big.release()
	assert.True(t, a.idle())
}

func TestIngestAdmission_ReleaseIsSafeToRepeatAndAfterAFailedAdmit(t *testing.T) {
	a := newIngestAdmission(2, 64*100, 20*time.Millisecond)
	hold, err := a.enter(context.Background(), "user:a", "user:a")
	require.NoError(t, err)
	require.NoError(t, admitTicket(hold, context.Background(), 100))

	blocked, err := a.enter(context.Background(), "user:b", "user:b")
	require.NoError(t, err)
	require.ErrorIs(t, admitTicket(blocked, context.Background(), 100), errIngestBusy)
	blocked.release()
	blocked.release()

	hold.release()
	hold.release()
	assert.True(t, a.idle(), "a double release must not hand out anything twice")
	tk, err := a.enter(context.Background(), "user:c", "user:c")
	require.NoError(t, err)
	require.NoError(t, admitTicket(tk, context.Background(), 100))
	tk.release()
}

func TestIngestAdmission_AClientThatLeavesWhileQueuedLeavesNothingBehind(t *testing.T) {
	a := newIngestAdmission(2, 0, time.Minute)
	first, err := a.enter(context.Background(), "user:a", "user:a")
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := a.enter(ctx, "user:a", "user:a"); done <- err }()
	time.Sleep(20 * time.Millisecond)
	cancel()
	require.ErrorIs(t, <-done, context.Canceled)
	first.release()
	assert.True(t, a.idle())
}

// An ingest that the client abandoned while it waited for a slot never starts.
func TestIngestReport_AbandonedWaitDoesNotRunTheUseCase(t *testing.T) {
	var runs int
	var mu sync.Mutex
	mock := &mockUsecases{ingestReportFn: func(context.Context, usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
		mu.Lock()
		runs++
		mu.Unlock()
		return &usecase.IngestReportOutput{ReportID: "r"}, nil
	}}
	h := NewHandler(mock)
	h.ingest = newIngestAdmission(1, 0, time.Minute)
	hold, err := h.ingest.enter(context.Background(), "user:other", "user:other")
	require.NoError(t, err)
	require.NoError(t, admitTicket(hold, context.Background(), 10))
	defer hold.release()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	req := httptest.NewRequest("POST", "/api/v1/reports", ingestBody(100)).WithContext(ctx)
	req = req.WithContext(auth.ContextWithIdentity(req.Context(), &auth.Identity{UserID: "u-admin", Role: auth.RoleAdmin}))
	h.IngestReport(httptest.NewRecorder(), req)

	mu.Lock()
	defer mu.Unlock()
	assert.Zero(t, runs, "a client that gave up while queued must not start an ingest")
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

// admitTicket takes everything an ingest needs once its body is known: the
// memory reservation, then the place and slot.
func admitTicket(tk *ingestTicket, ctx context.Context, rawBytes int) error {
	if err := tk.reserve(ctx, rawBytes); err != nil {
		return err
	}
	return tk.claim(ctx)
}
