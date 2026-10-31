package watcher

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func numberedNotifications(n int) []Notification {
	out := make([]Notification, n)
	for i := range out {
		out[i] = Notification{Title: fmt.Sprintf("finding %03d", i), CVE: fmt.Sprintf("CVE-2024-%04d", i)}
	}
	return out
}

func TestChunkNotificationsKeepsOrderAndBound(t *testing.T) {
	for _, tc := range []struct {
		total int
		sizes []int
	}{
		{0, nil},
		{1, []int{1}},
		{50, []int{50}},
		{51, []int{50, 1}},
		{120, []int{50, 50, 20}},
	} {
		chunks := chunkNotifications(numberedNotifications(tc.total), 50)
		var sizes []int
		next := 0
		for _, c := range chunks {
			sizes = append(sizes, len(c))
			for _, n := range c {
				assert.Equal(t, fmt.Sprintf("finding %03d", next), n.Title)
				next++
			}
		}
		assert.Equal(t, tc.sizes, sizes, "total %d", tc.total)
		assert.Equal(t, tc.total, next)
	}
}

type recordedPosts struct {
	mu     sync.Mutex
	bodies [][]byte
}

func (r *recordedPosts) server(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		b, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		r.bodies = append(r.bodies, b)
		r.mu.Unlock()
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Slack rejects a message with more than 100 attachments, so a round that
// created 120 findings goes out as consecutive messages of at most 50.
func TestSlackNotifierSplitsLargeBatches(t *testing.T) {
	var rec recordedPosts
	srv := rec.server(t)
	logger, _ := newTestLogger()
	n := NewSlackNotifier(srv.URL, "", logger)

	require.NoError(t, n.Notify(context.Background(), numberedNotifications(120)))

	require.Len(t, rec.bodies, 3)
	next := 0
	for i, want := range []int{50, 50, 20} {
		var p slackPayload
		require.NoError(t, json.Unmarshal(rec.bodies[i], &p))
		assert.Len(t, p.Attachments, want)
		assert.Equal(t, fmt.Sprintf("CVE watcher: %d new finding(s)", want), p.Text)
		for _, a := range p.Attachments {
			assert.Equal(t, fmt.Sprintf("finding %03d", next), a.Title)
			next++
		}
	}
}

func TestWebhookNotifierSplitsLargeBatches(t *testing.T) {
	var rec recordedPosts
	srv := rec.server(t)
	logger, _ := newTestLogger()
	n := NewWebhookNotifier(srv.URL, "", logger)

	require.NoError(t, n.Notify(context.Background(), numberedNotifications(webhookMaxRows+1)))

	require.Len(t, rec.bodies, 2)
	var first, second webhookPayload
	require.NoError(t, json.Unmarshal(rec.bodies[0], &first))
	require.NoError(t, json.Unmarshal(rec.bodies[1], &second))
	assert.Equal(t, WebhookEventCreated, second.Event)
	assert.Len(t, first.Notifications, webhookMaxRows)
	require.Len(t, second.Notifications, 1)
	assert.Equal(t, fmt.Sprintf("finding %03d", webhookMaxRows), second.Notifications[0].Title)
}
