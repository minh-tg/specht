package watcher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// notifierCases builds each channel against a URL, with the retry sleeper
// stubbed out, and returns it as a function that sends one notification and
// returns what the notifier logged.
func notifierCases(url string) map[string]func(t *testing.T) string {
	noSleep := func(context.Context, time.Duration) error { return nil }
	return map[string]func(t *testing.T) string{
		"slack": func(t *testing.T) string {
			logger, logs := newTestLogger()
			n := NewSlackNotifier(url, "", logger)
			n.sleeper = noSleep
			require.NoError(t, n.Notify(context.Background(), []Notification{testNotification()}))
			return logs.String()
		},
		"webhook": func(t *testing.T) string {
			logger, logs := newTestLogger()
			n := NewWebhookNotifier(url, "", logger)
			n.sleeper = noSleep
			require.NoError(t, n.Notify(context.Background(), []Notification{testNotification()}))
			return logs.String()
		},
	}
}

// The internal target listens on loopback, which the notifier client admits
// for a loopback webhook URL, so only the redirect block keeps the notifier
// away from it.
func TestNotifiersRefuseRedirects(t *testing.T) {
	var internalHits atomic.Int32
	internal := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		internalHits.Add(1)
	}))
	t.Cleanup(internal.Close)
	front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, internal.URL+"/admin", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(front.Close)

	for name, send := range notifierCases(front.URL) {
		t.Run(name, func(t *testing.T) {
			logs := send(t)
			assert.Zero(t, internalHits.Load(), "the notifier followed the redirect")
			assert.Contains(t, logs, "redirects are not allowed")
		})
	}
}

func TestNotifiersRefuseNonPublicAddresses(t *testing.T) {
	for _, url := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.5:8080/hook",
		"http://[fd00::1]/hook",
	} {
		for name, send := range notifierCases(url) {
			t.Run(name+" "+url, func(t *testing.T) {
				assert.Contains(t, send(t), "non-public address")
			})
		}
	}
}
