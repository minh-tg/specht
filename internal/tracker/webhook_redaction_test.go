package tracker

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type logSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *logSink) log(msg string, args ...any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, fmt.Sprint(append([]any{msg}, args...)...))
}

func (s *logSink) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

// Tracker endpoints may embed a token in the path or query. Neither the
// delivery line nor a transport error may write it to the log.
func TestWebHookTrackerLogsDoNotContainTheEndpointPathOrQuery(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	dead := ln.Addr().String()
	require.NoError(t, ln.Close())

	ok := srv.URL + "/hooks/TOKEN-abc123?key=SECRETKEY"
	failing := "http://" + dead + "/hooks/TOKEN-abc123?key=SECRETKEY"

	sink := &logSink{}
	tr := newTestWebhookTracker(t, WebHookTrackerConfig{Endpoints: []string{ok, failing}}, sink.log)
	_, err = tr.CreateIssue(context.Background(), Event{Type: EventCreated, Fingerprint: "fp"})
	require.NoError(t, err)
	waitFor(t, "both deliveries logged", func() bool {
		s := sink.String()
		return strings.Contains(s, "webhook dispatched") && strings.Contains(s, "webhook dispatch failed")
	})

	logs := sink.String()
	assert.Contains(t, logs, srv.URL, "the host stays")
	assert.Contains(t, logs, "connection refused", "the cause stays")
	assert.NotContains(t, logs, "TOKEN-abc123")
	assert.NotContains(t, logs, "SECRETKEY")
}
