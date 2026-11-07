package usecase

import (
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
)

func watcherTestTimePtr(t time.Time) *time.Time { return &t }

func TestWatcherStatusFromState_AttemptWithoutSuccessBecomesStale(t *testing.T) {
	t.Setenv("WATCHER_POLL_INTERVAL", "1h")

	resp := watcherStatusFromState(port.WatcherState{
		LastPollAttemptAt: watcherTestTimePtr(time.Now().Add(-3 * time.Hour)),
	}, watcherStalenessWindow(nil))

	assert.True(t, resp.Stale)
	assert.False(t, resp.Healthy)
}

func TestWatcherStatusFromState_NoAttemptIsColdStart(t *testing.T) {
	t.Setenv("WATCHER_POLL_INTERVAL", "1h")

	resp := watcherStatusFromState(port.WatcherState{}, watcherStalenessWindow(nil))

	assert.False(t, resp.Stale)
	assert.True(t, resp.Healthy)
}

// A project polled weekly is not late after a day, so a window built only from
// WATCHER_POLL_INTERVAL called a working watcher stale.
func TestWatcherStalenessWindowCoversTheLongestEnabledInterval(t *testing.T) {
	t.Setenv("WATCHER_POLL_INTERVAL", "1h")
	week := int32(7 * 24 * 60 * 60)

	assert.Equal(t, 2*time.Hour, watcherStalenessWindow(nil))
	assert.Equal(t, 14*24*time.Hour, watcherStalenessWindow([]port.Project{
		{CveWatcherEnabled: true, CveWatcherIntervalSecs: 60},
		{CveWatcherEnabled: true, CveWatcherIntervalSecs: week},
	}))
	assert.Equal(t, 2*time.Hour, watcherStalenessWindow([]port.Project{
		{CveWatcherEnabled: false, CveWatcherIntervalSecs: week},
	}), "a project with the watcher off does not widen the window")

	dayAgo := time.Now().Add(-24 * time.Hour)
	resp := watcherStatusFromState(port.WatcherState{LastSuccessfulPollAt: &dayAgo}, watcherStalenessWindow([]port.Project{
		{CveWatcherEnabled: true, CveWatcherIntervalSecs: week},
	}))
	assert.False(t, resp.Stale)
	assert.True(t, resp.Healthy)
}
