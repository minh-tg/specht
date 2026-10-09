package usecase

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/intel"
	"github.com/minh-tg/specht/internal/port"
)

const (
	intelTestFindingID = "00000000-0000-0000-0000-000000000021"
	intelTestCVE       = "CVE-2024-9143"
)

// gatedIntelProvider stands in for the EPSS feed. Fetch blocks until release
// is called, so a test controls when a background refresh completes. It counts
// the fetches that reached the feed.
type gatedIntelProvider struct {
	gate chan struct{}
	once sync.Once
	err  error

	mu    sync.Mutex
	calls int
}

func newGatedIntelProvider(err error) *gatedIntelProvider {
	return &gatedIntelProvider{gate: make(chan struct{}), err: err}
}

func (p *gatedIntelProvider) Name() string { return "epss" }

func (p *gatedIntelProvider) Fetch(ctx context.Context, _ []string) (map[string]intel.Record, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()

	select {
	case <-p.gate:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(5 * time.Second):
		return nil, errors.New("gate was never released")
	}
	if p.err != nil {
		return nil, p.err
	}
	score := 0.97
	return map[string]intel.Record{
		intelTestCVE: {CVEID: intelTestCVE, EPSS: &score, EPSSDate: "2026-09-01"},
	}, nil
}

func (p *gatedIntelProvider) release() {
	p.once.Do(func() { close(p.gate) })
}

func (p *gatedIntelProvider) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// newIntelTestUsecases builds a Usecases whose finding read resolves one
// CVE-shaped vulnerability dimension and whose intel store uses provider.
func newIntelTestUsecases(provider intel.Provider) *Usecases {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return makeFindingRow(1), nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{ToolName: "trivy", LocationSummary: "alpine:3.20"}, nil
	}
	fr.listDimensionsFn = func(ctx context.Context, findingID string) ([]port.FindingDimension, error) {
		return []port.FindingDimension{{Key: "vulnerability_id", Value: intelTestCVE}}, nil
	}
	return New(Deps{
		Stores: memberFindingDeps(fr),
		Intel:  intel.NewStore(time.Hour, nil, provider),
	})
}

func TestGetFinding_ReturnsWithoutWaitingOnIntelRefresh(t *testing.T) {
	provider := newGatedIntelProvider(nil)
	t.Cleanup(provider.release)
	uc := newIntelTestUsecases(provider)

	reqCtx, cancelReq := context.WithCancel(memberSessionCtx())
	start := time.Now()
	finding, err := uc.GetFinding(reqCtx, intelTestFindingID)
	elapsed := time.Since(start)
	require.NoError(t, err)
	assert.Less(t, elapsed, 100*time.Millisecond, "a detail read must not wait on the feed")
	assert.Nil(t, finding.Intel, "nothing is cached yet, so the read carries no intel")

	// The request is gone before the refresh completes. The refresh runs on a
	// detached context and must still land.
	cancelReq()
	provider.release()
	uc.intelRefresh.wg.Wait()

	finding, err = uc.GetFinding(memberSessionCtx(), intelTestFindingID)
	require.NoError(t, err)
	require.NotNil(t, finding.Intel, "the refreshed record is served on the next read")
	assert.Equal(t, intelTestCVE, finding.Intel.CVEID)
	require.NotNil(t, finding.Intel.EPSS)
	assert.InDelta(t, 0.97, *finding.Intel.EPSS, 0.0001)
	assert.Equal(t, 1, provider.callCount())
}

func TestGetFinding_ConcurrentMissesStartOneRefresh(t *testing.T) {
	provider := newGatedIntelProvider(nil)
	t.Cleanup(provider.release)
	uc := newIntelTestUsecases(provider)

	// Every read finishes while the feed is still blocked, so all of them
	// race against the one refresh in flight.
	var reads sync.WaitGroup
	for range 8 {
		reads.Add(1)
		go func() {
			defer reads.Done()
			_, err := uc.GetFinding(memberSessionCtx(), intelTestFindingID)
			assert.NoError(t, err)
		}()
	}
	reads.Wait()

	provider.release()
	uc.intelRefresh.wg.Wait()
	assert.Equal(t, 1, provider.callCount(), "concurrent misses for one CVE share one provider call")
}

func TestGetFinding_FailedRefreshIsNotRetriedWithinBackoff(t *testing.T) {
	provider := newGatedIntelProvider(errors.New("feed unreachable"))
	provider.release()
	uc := newIntelTestUsecases(provider)

	clock := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	uc.intelRefresh.now = func() time.Time { return clock }

	_, err := uc.GetFinding(memberSessionCtx(), intelTestFindingID)
	require.NoError(t, err)
	uc.intelRefresh.wg.Wait()
	require.Equal(t, 1, provider.callCount())

	for range 3 {
		finding, err := uc.GetFinding(memberSessionCtx(), intelTestFindingID)
		require.NoError(t, err)
		assert.Nil(t, finding.Intel, "a failed refresh leaves no record behind")
	}
	uc.intelRefresh.wg.Wait()
	assert.Equal(t, 1, provider.callCount(), "an offline feed is not called again inside the backoff")

	clock = clock.Add(intelRetryBackoff + time.Second)
	_, err = uc.GetFinding(memberSessionCtx(), intelTestFindingID)
	require.NoError(t, err)
	uc.intelRefresh.wg.Wait()
	assert.Equal(t, 2, provider.callCount(), "the feed is retried once the backoff has elapsed")
}
