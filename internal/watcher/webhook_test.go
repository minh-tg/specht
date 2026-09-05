package watcher

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildWebhookPayload_Envelope(t *testing.T) {
	body, err := BuildWebhookPayload([]Notification{NotificationFromDecision(sampleFindings(), "acme-web")})
	require.NoError(t, err)
	var env struct {
		Event         string `json:"event"`
		Notifications []struct {
			Title    string `json:"title"`
			CVE      string `json:"cve"`
			Package  string `json:"package"`
			Project  string `json:"project"`
			Severity string `json:"severity"`
			Link     string `json:"link"`
		} `json:"notifications"`
	}
	require.NoError(t, json.Unmarshal(body, &env))
	assert.Equal(t, WebhookEventCreated, env.Event)
	require.Len(t, env.Notifications, 1)
	n := env.Notifications[0]
	assert.Equal(t, "Prototype pollution in lodash", n.Title)
	assert.Equal(t, "CVE-2019-10744", n.CVE)
	assert.Equal(t, "acme-web", n.Project)
}

func TestWebhookNotify_DeliversSignedBatch(t *testing.T) {
	var gotBody []byte
	var gotSig, gotCT string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf [4096]byte
		n, _ := r.Body.Read(buf[:])
		gotBody = buf[:n]
		gotSig = r.Header.Get(SlackSignatureHeader)
		gotCT = r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewWebhookNotifier(srv.URL, "secret", nil)
	require.NoError(t, n.Notify(context.Background(),
		[]Notification{NotificationFromDecision(sampleFindings(), "acme-web")}))
	assert.Equal(t, "application/json", gotCT)
	assert.Equal(t, SignSlackBody(gotBody, "secret"), gotSig, "same HMAC scheme as Slack")
	var env struct {
		Event string `json:"event"`
	}
	require.NoError(t, json.Unmarshal(gotBody, &env))
	assert.Equal(t, WebhookEventCreated, env.Event)
}

func TestWebhookNotify_DisabledAndEmptyAreNoOps(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
	}))
	defer srv.Close()

	require.NoError(t, NewWebhookNotifier("", "s", nil).
		Notify(context.Background(), []Notification{{Title: "x"}}))
	require.NoError(t, NewWebhookNotifier(srv.URL, "s", nil).
		Notify(context.Background(), nil))
	assert.Equal(t, int32(0), calls.Load())
}

func TestWebhookNotify_RetryThenSwallow(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	n := NewWebhookNotifier(srv.URL, "", nil)
	var sleeps []time.Duration
	n.sleeper = recordSleeper(&sleeps)
	require.NoError(t, n.Notify(context.Background(), []Notification{{Title: "x"}}))
	assert.Equal(t, int32(3), calls.Load())
	assert.Equal(t, []time.Duration{500 * time.Millisecond, time.Second}, sleeps)

	// Permanent failure is swallowed, never returned.
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer dead.Close()
	d := NewWebhookNotifier(dead.URL, "", nil)
	d.sleeper = recordSleeper(&sleeps)
	require.NoError(t, d.Notify(context.Background(), []Notification{{Title: "x"}}))
}

func TestFanoutNotifier_DeliversToAll(t *testing.T) {
	var a, b atomic.Int32
	mk := func(c *atomic.Int32) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
	}
	srvA := mk(&a)
	defer srvA.Close()
	srvB := mk(&b)
	defer srvB.Close()

	f := NewFanoutNotifier(
		NewWebhookNotifier(srvA.URL, "", nil),
		NewSlackNotifier(srvB.URL, "", nil),
		nil,
	)
	require.NoError(t, f.Notify(context.Background(), []Notification{{Title: "x"}}))
	assert.Equal(t, int32(1), a.Load())
	assert.Equal(t, int32(1), b.Load())

	broken := NewWebhookNotifier("http://127.0.0.1:1", "", nil)
	broken.client.Timeout = time.Millisecond
	broken.sleeper = func(ctx context.Context, _ time.Duration) error { return nil }
	require.NoError(t, NewFanoutNotifier(broken).Notify(context.Background(), []Notification{{Title: "x"}}))
}

func TestFanoutNotifier_OneDeadChannelDoesNotBlockOthers(t *testing.T) {
	var got atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	dead := NewWebhookNotifier("http://127.0.0.1:1", "", nil)
	dead.client.Timeout = time.Millisecond
	dead.sleeper = func(ctx context.Context, _ time.Duration) error { return nil }
	alive := NewWebhookNotifier(srv.URL, "", nil)
	f := NewFanoutNotifier(dead, alive)
	require.NoError(t, f.Notify(context.Background(), []Notification{{Title: "x"}}))
	assert.Equal(t, int32(1), got.Load())
}
