package tracker

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// waitFor polls until cond reports true. Webhook delivery is asynchronous
// by design (a dead endpoint must never block the caller), so tests that
// assert a POST landed must wait for the background delivery rather than
// check immediately after CreateIssue/UpdateIssue returns.
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	require.Eventually(t, cond, 2*time.Second, 5*time.Millisecond, "timed out waiting for %s", what)
}

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

	waitFor(t, "webhook delivery", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(received) == 1
	})
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

	waitFor(t, "fan-out to both endpoints", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return count == 2
	})
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

	waitFor(t, "webhook delivery", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(received) == 1
	})
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

func TestWebHookTracker_DeadEndpointDoesNotBlockCreateIssue(t *testing.T) {
	// A listener that accepts the connection and then stalls without
	// responding. The client-side 10s timeout would otherwise make
	// CreateIssue block ~10s per dead endpoint; dispatch must be async
	// so the caller returns promptly regardless.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	// Closing the listener is test teardown; Accept exits when it is closed.
	defer func() {
		_ = l.Close()
	}()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// The client timeout closes this test connection; cleanup is best-effort.
				defer func() {
					_ = c.Close()
				}()
				// Read the request, then stall until the server closes.
				_, _ = io.Copy(io.Discard, c)
			}(c)
		}
	}()

	tr := NewWebHookTracker(WebHookTrackerConfig{
		Endpoints: []string{"http://" + l.Addr().String()},
	}, nil)

	start := time.Now()
	id, err := tr.CreateIssue(context.Background(), Event{Type: EventCreated, Fingerprint: "fp"})
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.Equal(t, IssueID("fp"), id)
	assert.Less(t, elapsed, 5*time.Second,
		"CreateIssue must return promptly while delivery happens in the background; took %s", elapsed)
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

func TestWebHookTracker_SignedPayload(t *testing.T) {
	const secret = "sekret"
	var mu sync.Mutex
	var gotHeader string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		gotHeader = r.Header.Get(WebHookSignatureHeader)
		gotBody = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := NewWebHookTracker(WebHookTrackerConfig{
		Endpoints: []string{srv.URL},
		Secret:    secret,
	}, func(msg string, args ...any) {})

	_, err := tr.CreateIssue(context.Background(), Event{
		Type: EventCreated, FindingID: "find-1", Fingerprint: "fp1",
	})
	require.NoError(t, err)

	waitFor(t, "signed webhook delivery", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return gotHeader != ""
	})
	mu.Lock()
	defer mu.Unlock()
	// Signature must cover the exact raw bytes the server received, using
	// the same HMAC-SHA256 scheme as the watcher notifiers.
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(gotBody)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(gotHeader), []byte(want)) {
		t.Errorf("X-Specht-Signature = %q, want %q", gotHeader, want)
	}
	if !strings.HasPrefix(gotHeader, "sha256=") {
		t.Errorf("signature %q lacks sha256= prefix", gotHeader)
	}
}

func TestWebHookTracker_NoSignatureWithoutSecret(t *testing.T) {
	var mu sync.Mutex
	var gotHeader string
	delivered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHeader = r.Header.Get(WebHookSignatureHeader)
		mu.Unlock()
		select {
		case <-delivered:
		default:
			close(delivered)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tr := NewWebHookTracker(WebHookTrackerConfig{
		Endpoints: []string{srv.URL},
	}, nil)

	_, err := tr.CreateIssue(context.Background(), Event{Type: EventCreated, Fingerprint: "fp"})
	require.NoError(t, err)

	select {
	case <-delivered:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for webhook delivery")
	}
	mu.Lock()
	defer mu.Unlock()
	assert.Empty(t, gotHeader, "no signature header when no secret configured")
}

func TestWebHookTracker_BlocksSSRF(t *testing.T) {
	tr := NewWebHookTracker(WebHookTrackerConfig{
		Endpoints: []string{"http://169.254.169.254/latest/meta-data/"},
	}, nil)
	id, err := tr.CreateIssue(context.Background(), Event{Type: EventCreated, Fingerprint: "fp"})
	require.NoError(t, err)
	assert.Equal(t, IssueID("fp"), id)
}
