package usecase

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/xMinhx/specht/internal/port"
)

func watcherTestTimePtr(t time.Time) *time.Time { return &t }

func TestWatcherStatusFromState_AttemptWithoutSuccessBecomesStale(t *testing.T) {
	t.Setenv("WATCHER_POLL_INTERVAL", "1h")

	resp := watcherStatusFromState(port.WatcherState{
		LastPollAttemptAt: watcherTestTimePtr(time.Now().Add(-3 * time.Hour)),
	})

	assert.True(t, resp.Stale)
	assert.False(t, resp.Healthy)
}

func TestWatcherStatusFromState_NoAttemptIsColdStart(t *testing.T) {
	t.Setenv("WATCHER_POLL_INTERVAL", "1h")

	resp := watcherStatusFromState(port.WatcherState{})

	assert.False(t, resp.Stale)
	assert.True(t, resp.Healthy)
}
