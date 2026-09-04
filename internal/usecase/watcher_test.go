package usecase

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

func TestWatcherStatusFromState_AttemptWithoutSuccessBecomesStale(t *testing.T) {
	t.Setenv("WATCHER_POLL_INTERVAL", "1h")

	resp := watcherStatusFromState(sqlc.WatcherState{
		LastPollAttemptAt: pgtype.Timestamptz{Time: time.Now().Add(-3 * time.Hour), Valid: true},
	})

	assert.True(t, resp.Stale)
	assert.False(t, resp.Healthy)
}

func TestWatcherStatusFromState_NoAttemptIsColdStart(t *testing.T) {
	t.Setenv("WATCHER_POLL_INTERVAL", "1h")

	resp := watcherStatusFromState(sqlc.WatcherState{})

	assert.False(t, resp.Stale)
	assert.True(t, resp.Healthy)
}
