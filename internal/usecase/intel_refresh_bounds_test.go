package usecase

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/intel"
	"github.com/minh-tg/specht/internal/port"
)

// blockingIntel stands in for a slow feed. It counts the refreshes in flight,
// the most it saw at once, and every refresh it started.
type blockingIntel struct {
	inflight atomic.Int64
	peak     atomic.Int64
	started  atomic.Int64
	release  chan struct{}
	once     sync.Once
}

func newBlockingIntel() *blockingIntel { return &blockingIntel{release: make(chan struct{})} }

func (b *blockingIntel) open() { b.once.Do(func() { close(b.release) }) }

func (b *blockingIntel) Lookup(string) (intel.Record, bool, bool) {
	return intel.Record{}, false, false
}

func (b *blockingIntel) Refresh(ctx context.Context, _ []string) error {
	b.started.Add(1)
	n := b.inflight.Add(1)
	for {
		peak := b.peak.Load()
		if n <= peak || b.peak.CompareAndSwap(peak, n) {
			break
		}
	}
	defer b.inflight.Add(-1)
	select {
	case <-b.release:
	case <-ctx.Done():
	}
	return nil
}

// Reads of findings with many distinct CVE ids must not start a refresh each.
// At most intelRefreshWorkers run at once, intelRefreshQueue wait, and the
// rest are skipped.
func TestIntelRefresherBoundsConcurrentRefreshes(t *testing.T) {
	const reads = 5000
	store := newBlockingIntel()
	t.Cleanup(store.open)
	var r intelRefresher
	for i := range reads {
		r.schedule(context.Background(), store, fmt.Sprintf("CVE-2099-%05d", i))
	}
	require.Eventually(t, func() bool { return store.inflight.Load() == intelRefreshWorkers }, 5*time.Second, 5*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	assert.EqualValues(t, intelRefreshWorkers, store.inflight.Load(), "only the workers run")
	assert.EqualValues(t, intelRefreshWorkers, store.started.Load())

	store.open()
	r.wg.Wait()
	assert.LessOrEqual(t, store.peak.Load(), int64(intelRefreshWorkers))
	assert.EqualValues(t, intelRefreshWorkers+intelRefreshQueue, store.started.Load(), "the rest were skipped, not run")
}

// A skipped CVE is neither marked in flight nor held back, so a later read
// schedules it once there is room.
func TestIntelRefresherSkipsWhenFullAndAcceptsAgainAfterDraining(t *testing.T) {
	store := newBlockingIntel()
	t.Cleanup(store.open)
	var r intelRefresher
	for i := range intelRefreshWorkers + intelRefreshQueue {
		r.schedule(context.Background(), store, fmt.Sprintf("CVE-2099-%05d", i))
	}
	skipped := "CVE-2098-00001"
	r.schedule(context.Background(), store, skipped)
	r.mu.Lock()
	_, inflight := r.inflight[skipped]
	_, held := r.retryAfter[skipped]
	r.mu.Unlock()
	assert.False(t, inflight, "a skipped CVE is not marked in flight")
	assert.False(t, held, "and not held back")

	store.open()
	r.wg.Wait()
	before := store.started.Load()
	r.schedule(context.Background(), store, skipped)
	r.wg.Wait()
	assert.Equal(t, before+1, store.started.Load(), "the CVE is refreshed once there is room")
}

// A finding id that only starts with "CVE-" never reaches a feed.
func TestGetFinding_IgnoresMalformedCVEIDsForIntel(t *testing.T) {
	provider := newGatedIntelProvider(nil)
	t.Cleanup(provider.release)
	uc := newIntelTestUsecases(provider)
	fr := uc.deps.Stores.Findings.(*mockFindingRepo)
	for _, id := range []string{"CVE-x", "CVE-2024-1", "CVE-2024-12345678", "CVE-2024-1234,CVE-2024-5678", "CVE-2024-1234/../x"} {
		fr.listDimensionsFn = func(context.Context, string) ([]port.FindingDimension, error) {
			return []port.FindingDimension{{Key: "vulnerability_id", Value: id}}, nil
		}
		finding, err := uc.GetFinding(memberSessionCtx(), intelTestFindingID)
		require.NoError(t, err)
		assert.Nil(t, finding.Intel, id)
	}
	provider.release()
	uc.intelRefresh.wg.Wait()
	assert.Equal(t, 0, provider.callCount(), "no feed request for a malformed id")
}
