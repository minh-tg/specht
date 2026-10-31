package watcher

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A Slack incoming-webhook URL is itself the credential, and net/http prints
// the full URL in every transport error. The log must carry the host and the
// cause only.
func TestNotifiersDoNotLogTheWebhookURLOnTransportError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close()) // nothing listens: connection refused
	url := "http://" + addr + "/services/T0000/B0000/XXXXSECRETTOKENXXXX?key=QUERYSECRET"
	noSleep := func(context.Context, time.Duration) error { return nil }

	slackLogger, slackLogs := newTestLogger()
	slack := NewSlackNotifier(url, "", slackLogger)
	slack.sleeper = noSleep
	require.NoError(t, slack.Notify(context.Background(), []Notification{testNotification()}))

	hookLogger, hookLogs := newTestLogger()
	hook := NewWebhookNotifier(url, "", hookLogger)
	hook.sleeper = noSleep
	require.NoError(t, hook.Notify(context.Background(), []Notification{testNotification()}))

	for name, logs := range map[string]string{"slack": slackLogs.String(), "webhook": hookLogs.String()} {
		assert.Contains(t, logs, "transport error", name)
		assert.Contains(t, logs, "http://"+addr, name+": the host stays so an operator can tell which endpoint failed")
		assert.Contains(t, logs, "connection refused", name+": the cause stays")
		assert.NotContains(t, logs, "XXXXSECRETTOKENXXXX", name)
		assert.NotContains(t, logs, "QUERYSECRET", name)
		assert.NotContains(t, logs, "/services/", name)
	}
}
