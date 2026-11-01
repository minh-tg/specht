package server

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/usecase"
)

func paddedReport(project string, length int) string {
	prefix := `{"project":"` + project + `","scanner":"trivy","raw_data":"`
	return prefix + strings.Repeat("z", length-len(prefix)-2) + `"}`
}

// An upload waiting for its decoding charge does not hold up smaller uploads
// whose memory is free: the waiter does not sit in the semaphore's queue, which
// would make every later request wait behind it.
func TestIngestReport_SmallUploadIsNotHeldUpByALargeOneWaitingForItsCharge(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	mock := &mockUsecases{ingestReportFn: func(_ context.Context, in usecase.IngestReportInput) (*usecase.IngestReportOutput, error) {
		if in.ProjectSlug == "my-app" {
			entered <- struct{}{}
			<-release
		}
		return &usecase.IngestReportOutput{ReportID: "rep-1"}, nil
	}}
	// Room for 1200 bytes of report at the full charge.
	adm := newIngestAdmission(8, 64*1200, time.Second)
	var bytesRead atomic.Int64
	srv := ingestPrincipalServer(t, adm, mock, &bytesRead)
	released := false
	releaseHolder := func() {
		if !released {
			released = true
			close(release)
		}
	}
	t.Cleanup(releaseHolder)

	holder := make(chan int, 1)
	go func() {
		status, _, _ := postIngest(t, srv, "key-0", paddedReport("my-app", 900))
		holder <- status
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the first upload never reached the use case")
	}

	// 800 bytes need 51200 of the 19200 that is free: this upload waits.
	big := make(chan int, 1)
	go func() {
		status, _, _ := postIngest(t, srv, "other-1", paddedReport("other-app", 800))
		big <- status
	}()
	time.Sleep(200 * time.Millisecond)

	start := time.Now()
	status, _, _ := postIngest(t, srv, "third-1", paddedReport("third-app", 100))
	elapsed := time.Since(start)
	assert.Equal(t, http.StatusCreated, status)
	assert.Less(t, elapsed, 300*time.Millisecond, "the small upload did not queue behind the large one")

	assert.Equal(t, http.StatusServiceUnavailable, <-big, "the large upload gives up after the queue wait")
	releaseHolder()
	assert.Equal(t, http.StatusCreated, <-holder)
	assert.Eventually(t, adm.idle, time.Second, 5*time.Millisecond)
}
