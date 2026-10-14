package lifecycle

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeReportReaper struct {
	mu     sync.Mutex
	cutoff time.Time
	reason string
	count  int64
	err    error
	calls  int
}

func (f *fakeReportReaper) FailStale(_ context.Context, cutoff time.Time, reason string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.cutoff, f.reason = cutoff, reason
	return f.count, f.err
}

func (f *fakeReportReaper) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestReapStaleReports_CutsOffAtTheGivenAge(t *testing.T) {
	reaper := &fakeReportReaper{count: 2}
	before := time.Now()

	n, err := ReapStaleReports(context.Background(), reaper, 30*time.Minute, quietLogger())

	require.NoError(t, err)
	assert.Equal(t, 2, n)
	assert.WithinDuration(t, before.Add(-30*time.Minute), reaper.cutoff, time.Minute)
	assert.NotEmpty(t, reaper.reason)
}

func TestReapStaleReports_PassesTheStoreErrorOn(t *testing.T) {
	reaper := &fakeReportReaper{err: errors.New("down")}

	_, err := ReapStaleReports(context.Background(), reaper, time.Hour, quietLogger())

	assert.ErrorContains(t, err, "down")
}

func TestRunStaleReportReaper_RejectsNonsenseTimings(t *testing.T) {
	reaper := &fakeReportReaper{}
	assert.Error(t, RunStaleReportReaper(context.Background(), reaper, 0, time.Hour, quietLogger()))
	assert.Error(t, RunStaleReportReaper(context.Background(), reaper, time.Minute, 0, quietLogger()))
}

func TestRunStaleReportReaper_SweepsOnStartAndOnEveryTick(t *testing.T) {
	reaper := &fakeReportReaper{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, RunStaleReportReaper(ctx, reaper, 10*time.Millisecond, time.Hour, quietLogger()))

	assert.Eventually(t, func() bool { return reaper.callCount() >= 3 }, time.Second, 5*time.Millisecond,
		"a report stranded by a crash is settled right after the restart, not one interval later")
}
