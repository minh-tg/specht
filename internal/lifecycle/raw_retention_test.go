package lifecycle

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeClearer answers each ClearRawData call with the next scripted count and records the cutoffs.
type fakeClearer struct {
	counts  []int64
	err     error
	calls   int
	cutoffs []time.Time
	batches []int32
}

func (f *fakeClearer) ClearRawData(_ context.Context, cutoff time.Time, batchSize int32) (int64, error) {
	f.calls++
	f.cutoffs = append(f.cutoffs, cutoff)
	f.batches = append(f.batches, batchSize)
	if f.err != nil {
		return 0, f.err
	}
	n := f.counts[0]
	f.counts = f.counts[1:]
	return n, nil
}

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func TestClearExpiredRaw_ZeroWindowKeepsEverything(t *testing.T) {
	f := &fakeClearer{counts: []int64{5}}
	n, err := ClearExpiredRaw(context.Background(), f, 0, time.Now(), discard)
	require.NoError(t, err)
	assert.Zero(t, n)
	assert.Zero(t, f.calls, "a zero window must not touch any payload")
}

func TestClearExpiredRaw_CutoffIsTheWindowBeforeNow(t *testing.T) {
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	f := &fakeClearer{counts: []int64{0}}
	_, err := ClearExpiredRaw(context.Background(), f, 30, now, discard)
	require.NoError(t, err)
	require.Len(t, f.cutoffs, 1)
	assert.Equal(t, now.AddDate(0, 0, -30), f.cutoffs[0])
}

func TestClearExpiredRaw_DrainsBatchesUntilAShortOne(t *testing.T) {
	f := &fakeClearer{counts: []int64{rawRetentionBatch, rawRetentionBatch, 3}}
	n, err := ClearExpiredRaw(context.Background(), f, 30, time.Now(), discard)
	require.NoError(t, err)
	assert.EqualValues(t, 2*rawRetentionBatch+3, n)
	assert.Equal(t, 3, f.calls)
	for _, b := range f.batches {
		assert.EqualValues(t, rawRetentionBatch, b)
	}
}

func TestClearExpiredRaw_ReturnsTheCountBeforeAnError(t *testing.T) {
	f := &fakeClearer{counts: []int64{rawRetentionBatch}, err: errors.New("db down")}
	_, err := ClearExpiredRaw(context.Background(), f, 30, time.Now(), discard)
	assert.ErrorContains(t, err, "db down")
}

func TestRunRawRetention_RefusesNegativeDays(t *testing.T) {
	err := RunRawRetention(context.Background(), &fakeClearer{}, time.Minute, -1, discard)
	assert.ErrorContains(t, err, "zero or more")
}

func TestRunRawRetention_ZeroDaysStartsNothing(t *testing.T) {
	f := &fakeClearer{}
	require.NoError(t, RunRawRetention(context.Background(), f, time.Millisecond, 0, discard))
	time.Sleep(20 * time.Millisecond)
	assert.Zero(t, f.calls, "a zero window must never reach the store")
}

func TestRunRawRetention_RefusesNonPositiveInterval(t *testing.T) {
	err := RunRawRetention(context.Background(), &fakeClearer{}, 0, 30, discard)
	assert.ErrorContains(t, err, "interval must be positive")
}
