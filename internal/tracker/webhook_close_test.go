package tracker

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestWebhookCloseStopsWorkersAndConcurrentDispatch(t *testing.T) {
	started := make(chan struct{}, webhookWorkers)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case started <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	tr := NewWebHookTracker(WebHookTrackerConfig{Endpoints: []string{srv.URL}, Timeout: time.Hour}, nil)
	tr.client = srv.Client()
	closer, ok := any(tr).(io.Closer)
	require.True(t, ok, "configured workers must have an owner-controlled shutdown")
	_, err := tr.CreateIssue(context.Background(), Event{Type: EventCreated, Fingerprint: "first"})
	require.NoError(t, err)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("delivery never started")
	}
	var senders sync.WaitGroup
	for i := 0; i < 8; i++ {
		senders.Go(func() {
			for n := 0; n < 100; n++ {
				_, _ = tr.CreateIssue(context.Background(), Event{Type: EventCreated, Fingerprint: "concurrent"})
			}
		})
	}
	done := make(chan error, 1)
	dispatcherCloser, ok := any(NewDispatcher(tr, nil)).(io.Closer)
	require.True(t, ok)
	go func() { done <- dispatcherCloser.Close() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(3 * time.Second):
		t.Fatal("close must cancel blocked network requests and stop workers")
	}
	senders.Wait()
	require.NoError(t, closer.Close(), "closing twice must be safe")
	require.Zero(t, tr.QueueDepth())
}
