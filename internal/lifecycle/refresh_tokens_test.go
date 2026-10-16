package lifecycle

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakePruner struct {
	mu      sync.Mutex
	batches []int64 // rows each call reports deleted, then zero
	calls   []pruneCall
	err     error
}

type pruneCall struct {
	expiredBefore, revokedBefore time.Time
	limit                        int
}

func (f *fakePruner) Prune(_ context.Context, expiredBefore, revokedBefore time.Time, limit int) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, pruneCall{expiredBefore, revokedBefore, limit})
	if f.err != nil {
		return 0, f.err
	}
	if len(f.batches) == 0 {
		return 0, nil
	}
	n := f.batches[0]
	f.batches = f.batches[1:]
	return n, nil
}

func (f *fakePruner) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func TestPruneRefreshTokens_DeletesExpiredNowAndRevokedAfterAWeek(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	pruner := &fakePruner{batches: []int64{3}}

	n, err := PruneRefreshTokens(context.Background(), pruner, now, quietLogger())

	require.NoError(t, err)
	assert.Equal(t, 3, n)
	require.Len(t, pruner.calls, 1)
	call := pruner.calls[0]
	assert.Equal(t, now, call.expiredBefore, "an expired token is deleted at once")
	assert.Equal(t, now.Add(-7*24*time.Hour), call.revokedBefore, "a revoked token stays for seven days")
	assert.Equal(t, RefreshPruneBatch, call.limit)
}

func TestPruneRefreshTokens_KeepsGoingWhileBatchesAreFull(t *testing.T) {
	pruner := &fakePruner{batches: []int64{int64(RefreshPruneBatch), int64(RefreshPruneBatch), 40}}

	n, err := PruneRefreshTokens(context.Background(), pruner, time.Now(), quietLogger())

	require.NoError(t, err)
	assert.Equal(t, 2*RefreshPruneBatch+40, n)
	assert.Equal(t, 3, pruner.callCount(), "a short batch means nothing is left")
}

func TestPruneRefreshTokens_BoundsTheWorkOfOneSweep(t *testing.T) {
	full := make([]int64, RefreshPruneMaxBatches*2)
	for i := range full {
		full[i] = int64(RefreshPruneBatch)
	}
	pruner := &fakePruner{batches: full}

	n, err := PruneRefreshTokens(context.Background(), pruner, time.Now(), quietLogger())

	require.NoError(t, err)
	assert.Equal(t, RefreshPruneMaxBatches, pruner.callCount(), "a backlog drains over several sweeps")
	assert.Equal(t, RefreshPruneMaxBatches*RefreshPruneBatch, n)
}

func TestPruneRefreshTokens_ReportsWhatItDeletedBeforeAnError(t *testing.T) {
	pruner := &fakePruner{batches: []int64{int64(RefreshPruneBatch)}}
	calls := 0
	failing := pruneFunc(func(ctx context.Context, e, r time.Time, limit int) (int64, error) {
		calls++
		if calls == 2 {
			return 0, errors.New("down")
		}
		return pruner.Prune(ctx, e, r, limit)
	})

	n, err := PruneRefreshTokens(context.Background(), failing, time.Now(), quietLogger())

	assert.ErrorContains(t, err, "down")
	assert.Equal(t, RefreshPruneBatch, n)
}

type pruneFunc func(context.Context, time.Time, time.Time, int) (int64, error)

func (f pruneFunc) Prune(ctx context.Context, e, r time.Time, limit int) (int64, error) {
	return f(ctx, e, r, limit)
}

func TestRunRefreshTokenPrune_RejectsNonPositiveInterval(t *testing.T) {
	for _, interval := range []time.Duration{0, -time.Second} {
		assert.Error(t, RunRefreshTokenPrune(context.Background(), &fakePruner{}, interval, quietLogger()), interval.String())
	}
}

// The trigger: one sweep as soon as it starts (which clears what accumulated
// while the server was down), then one per interval, until the context ends.
func TestRunRefreshTokenPrune_SweepsAtStartAndOnEveryTick(t *testing.T) {
	pruner := &fakePruner{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	require.NoError(t, RunRefreshTokenPrune(ctx, pruner, 10*time.Millisecond, quietLogger()))

	require.Eventually(t, func() bool { return pruner.callCount() >= 3 }, 5*time.Second, 5*time.Millisecond,
		"expected the start sweep and at least two ticks")

	cancel()
	time.Sleep(50 * time.Millisecond)
	settled := pruner.callCount()
	time.Sleep(60 * time.Millisecond)
	assert.Equal(t, settled, pruner.callCount(), "no sweep runs after the context ends")
}
