package tracker

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebHookTracker_CreateIssue(t *testing.T) {
	var mu sync.Mutex
	var received []Event
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev Event
		_ = json.Unmarshal(body, &ev)
		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := NewWebHookTracker(WebHookTrackerConfig{
		Endpoints: []string{srv.URL},
	}, func(msg string, args ...any) {})

	event := Event{
		Type:        EventCreated,
		FindingID:   "find-1",
		ProjectSlug: "my-app",
		Severity:    "high",
		Title:       "CVE-2024-1234",
		Fingerprint: "fp1",
		OccurredAt:  time.Now(),
	}

	id, err := tr.CreateIssue(context.Background(), event)
	require.NoError(t, err)
	assert.Equal(t, IssueID("fp1"), id)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 1)
	assert.Equal(t, EventCreated, received[0].Type)
	assert.Equal(t, "find-1", received[0].FindingID)
}

func TestWebHookTracker_FanOutMultiple(t *testing.T) {
	var mu sync.Mutex
	count := 0
	mk := func() http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			mu.Lock()
			count++
			mu.Unlock()
			w.WriteHeader(http.StatusOK)
		})
	}
	s1 := httptest.NewServer(mk())
	defer s1.Close()
	s2 := httptest.NewServer(mk())
	defer s2.Close()

	tr := NewWebHookTracker(WebHookTrackerConfig{
		Endpoints: []string{s1.URL, s2.URL},
	}, nil)

	event := Event{Type: EventCreated, FindingID: "f1", Fingerprint: "fp"}
	_, err := tr.CreateIssue(context.Background(), event)
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 2, count)
}

func TestWebHookTracker_NoEndpoints(t *testing.T) {
	tr := NewWebHookTracker(WebHookTrackerConfig{Endpoints: nil}, nil)
	id, err := tr.CreateIssue(context.Background(), Event{Type: EventCreated, Fingerprint: "fp"})
	require.NoError(t, err)
	assert.Empty(t, id)
}

func TestWebHookTracker_UpdateIssue(t *testing.T) {
	var received []Event
	var mu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var ev Event
		_ = json.Unmarshal(body, &ev)
		mu.Lock()
		received = append(received, ev)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	tr := NewWebHookTracker(WebHookTrackerConfig{Endpoints: []string{srv.URL}}, nil)
	err := tr.UpdateIssue(context.Background(), "issue-1", Event{
		Type:        EventVerifiedFixed,
		FindingID:   "find-1",
		ProjectSlug: "my-app",
	})
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.Len(t, received, 1)
	assert.Equal(t, EventVerifiedFixed, received[0].Type)
}

func TestWebHookTracker_EmptyEndpointsOnFailure(t *testing.T) {
	tr := NewWebHookTracker(WebHookTrackerConfig{Endpoints: nil}, nil)
	// Should not panic and should return nil error
	err := tr.UpdateIssue(context.Background(), "issue-1", Event{Type: EventRegression})
	assert.NoError(t, err)
}

func TestEnvWebHookURLs(t *testing.T) {
	env := func(key string) string {
		switch key {
		case "URLS":
			return "https://hooks.example.com/a, https://hooks.example.com/b ,"
		default:
			return ""
		}
	}
	urls := EnvWebHookURLs("URLS", env)
	assert.Equal(t, []string{"https://hooks.example.com/a", "https://hooks.example.com/b"}, urls)

	// Empty env var
	envEmpty := func(key string) string { return "" }
	assert.Nil(t, EnvWebHookURLs("URLS", envEmpty))
}
