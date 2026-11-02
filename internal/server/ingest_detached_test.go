package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/usecase"
)

// A client that hangs up cancels the request context. The write phase of the
// ingest must not see that: cut in half it leaves a processing report and
// findings no scan can close. It keeps the server's own deadline.
func TestIngestReport_WritePhaseSurvivesTheClientHangingUp(t *testing.T) {
	started := make(chan struct{})
	hungUp := make(chan struct{})
	var ctxErr error
	var hasDeadline bool
	mock := &mockUsecases{
		ingestReportFn: func(ctx context.Context, _ usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			close(started)
			<-hungUp
			ctxErr = ctx.Err()
			_, hasDeadline = ctx.Deadline()
			return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
		},
	}
	reqCtx, hangUp := context.WithCancel(context.Background())
	defer hangUp()
	req := httptest.NewRequest("POST", "/api/v1/reports",
		strings.NewReader(`{"project":"my-app","scanner":"trivy","raw_data":{"a":1}}`)).WithContext(reqCtx)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken(t))
	w := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth}).ServeHTTP(w, req)
	}()
	<-started
	hangUp()
	close(hungUp)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("handler did not return")
	}

	assert.NoError(t, ctxErr, "the use case ran on a context the hang-up could not cancel")
	assert.True(t, hasDeadline, "and it still has the server's deadline")
	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestDetachedContext_KeepsValuesAndDeadlineButNotCancellation(t *testing.T) {
	type key struct{}
	parent, cancelParent := context.WithTimeout(context.WithValue(context.Background(), key{}, "v"), time.Hour)
	deadline, _ := parent.Deadline()

	ctx, cancel := detachedContext(parent)
	defer cancel()
	cancelParent()

	require.NoError(t, ctx.Err())
	assert.Equal(t, "v", ctx.Value(key{}))
	got, ok := ctx.Deadline()
	require.True(t, ok)
	assert.Equal(t, deadline, got)

	short, cancelShort := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancelShort()
	expiring, cancelExpiring := detachedContext(short)
	defer cancelExpiring()
	<-expiring.Done()
	assert.ErrorIs(t, expiring.Err(), context.DeadlineExceeded, "the server's own deadline still ends the ingest")
}

// The response deadline is armed for the processing window plus a slack. An
// ingest that outlives the window is cut off inside that slack, so the caller
// receives the failure instead of a closed connection.
func TestIngestReport_WritePhaseEndsWithinTheProcessingWindow(t *testing.T) {
	var remaining time.Duration
	var hasDeadline bool
	mock := &mockUsecases{
		ingestReportFn: func(ctx context.Context, _ usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
			var deadline time.Time
			deadline, hasDeadline = ctx.Deadline()
			remaining = time.Until(deadline)
			return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
		},
	}
	req := httptest.NewRequest("POST", "/api/v1/reports",
		strings.NewReader(`{"project":"my-app","scanner":"trivy","raw_data":{"a":1}}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+testToken(t))
	w := httptest.NewRecorder()
	NewRouter(RouterConfig{Usecases: mock, JWTAuth: testJWTAuth}).ServeHTTP(w, req)

	require.Equal(t, http.StatusCreated, w.Code)
	require.True(t, hasDeadline)
	assert.LessOrEqual(t, remaining, ingestWindow, "the write phase may not run past the processing window")
	assert.Greater(t, remaining, ingestWindow-10*time.Second)
}
