package tracker

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type dispatchLog struct {
	mu    sync.Mutex
	lines []string
}

func (s *dispatchLog) log(msg string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprint(append([]any{msg}, args...)...))
}

func (s *dispatchLog) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

// The internal target listens on loopback, which the tracker client admits
// for a loopback endpoint, so only the redirect block keeps the tracker away
// from it.
func TestWebHookTrackerRefusesRedirect(t *testing.T) {
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { internalHits.Add(1) }))
	defer internal.Close()
	var frontHits atomic.Int32
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		frontHits.Add(1)
		http.Redirect(w, r, internal.URL+"/admin", http.StatusTemporaryRedirect)
	}))
	defer front.Close()

	sink := &dispatchLog{}
	tr := newTestWebhookTracker(t, WebHookTrackerConfig{Endpoints: []string{front.URL}}, sink.log)
	_, err := tr.CreateIssue(context.Background(), Event{Type: EventCreated, Fingerprint: "fp"})
	require.NoError(t, err)
	waitFor(t, "dispatch failure logged", func() bool { return strings.Contains(sink.String(), "redirects are not allowed") })
	assert.EqualValues(t, 1, frontHits.Load())
	assert.Zero(t, internalHits.Load(), "redirect target must not be reached")
}

func TestWebHookTrackerRefusesNonPublicAddresses(t *testing.T) {
	for _, endpoint := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5:8080/hook",
		"http://[fd00::1]/hook",
	} {
		sink := &dispatchLog{}
		tr := newTestWebhookTracker(t, WebHookTrackerConfig{Endpoints: []string{endpoint}}, sink.log)
		_, err := tr.CreateIssue(context.Background(), Event{Type: EventCreated, Fingerprint: "fp"})
		require.NoError(t, err)
		waitFor(t, "refusal logged for "+endpoint, func() bool {
			return strings.Contains(sink.String(), "refusing connection to non-public address")
		})
	}
}
