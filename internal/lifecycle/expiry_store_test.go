package lifecycle

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
)

// fakeAnalysisExpiryStore is an in-memory port.AnalysisExpiryStore.
type fakeAnalysisExpiryStore struct {
	expired []port.Finding
	err     error
	calls   atomic.Int64
}

func (f *fakeAnalysisExpiryStore) ExpireExpired(ctx context.Context) ([]port.Finding, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return f.expired, nil
}

// fakeWaiverExpiryStore is an in-memory port.WaiverExpiryStore.
type fakeWaiverExpiryStore struct {
	expired []port.Waiver
	ending  []port.Waiver
	err     error
	calls   atomic.Int64
}

func (f *fakeWaiverExpiryStore) ExpireExpired(ctx context.Context) ([]port.Waiver, error) {
	f.calls.Add(1)
	if f.err != nil {
		return nil, f.err
	}
	return f.expired, nil
}

func (f *fakeWaiverExpiryStore) ClaimExpiring(context.Context, time.Time) ([]port.Waiver, error) {
	return f.ending, nil
}

// fakeAnnouncer records what a sweep announced.
type fakeAnnouncer struct{ ending, ended []port.Waiver }

func (a *fakeAnnouncer) WaiversEnding(_ context.Context, w []port.Waiver) {
	a.ending = append(a.ending, w...)
}

func (a *fakeAnnouncer) WaiversEnded(_ context.Context, w []port.Waiver) {
	a.ended = append(a.ended, w...)
}

func TestSweepAnnouncesWhatEndedAndWhatIsEnding(t *testing.T) {
	store := &fakeWaiverExpiryStore{
		expired: []port.Waiver{{ID: "gone"}},
		ending:  []port.Waiver{{ID: "soon"}},
	}
	announcer := &fakeAnnouncer{}
	sweepAndAnnounce(context.Background(), store, announcer, time.Hour, slog.Default())
	if len(announcer.ended) != 1 || announcer.ended[0].ID != "gone" {
		t.Fatalf("ended: %v", announcer.ended)
	}
	if len(announcer.ending) != 1 || announcer.ending[0].ID != "soon" {
		t.Fatalf("ending: %v", announcer.ending)
	}
}

func TestSweepWithoutAnAnnouncerStillExpires(t *testing.T) {
	store := &fakeWaiverExpiryStore{expired: []port.Waiver{{ID: "gone"}}}
	sweepAndAnnounce(context.Background(), store, nil, time.Hour, slog.Default())
	if store.calls.Load() != 1 {
		t.Fatalf("calls: %d", store.calls.Load())
	}
}

func TestSweepExpiredFindings_StoreDriven(t *testing.T) {
	store := &fakeAnalysisExpiryStore{
		expired: []port.Finding{
			{ID: "f1", AnalysisState: "accepted_risk", GateEffect: "ignore"},
			{ID: "f2", AnalysisState: "accepted_risk", GateEffect: "ignore"},
		},
	}
	logger := slog.Default()

	n, err := SweepExpiredFindings(context.Background(), store, logger)
	requireNoError(t, err)
	assert.Equal(t, 2, n)
	assert.Equal(t, int64(1), store.calls.Load())

	// Error propagates from the store.
	store.err = assertAnError("db down")
	_, err = SweepExpiredFindings(context.Background(), store, logger)
	assert.ErrorContains(t, err, "db down")
}

func TestSweepExpiredFindings_NoExpired(t *testing.T) {
	store := &fakeAnalysisExpiryStore{}
	n, err := SweepExpiredFindings(context.Background(), store, slog.Default())
	requireNoError(t, err)
	assert.Zero(t, n)
}

func TestRunAnalysisExpiry_CancellationStops(t *testing.T) {
	store := &fakeAnalysisExpiryStore{expired: []port.Finding{{ID: "f1"}}}
	ctx, cancel := context.WithCancel(context.Background())

	RunAnalysisExpiry(ctx, store, 10*time.Millisecond, slog.Default())
	// Let a tick fire, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)

	assert.GreaterOrEqual(t, store.calls.Load(), int64(1), "ticker should have fired before cancellation")
}

func TestSweepExpiredWaivers_StoreDriven(t *testing.T) {
	store := &fakeWaiverExpiryStore{
		expired: []port.Waiver{{ID: "w1", Name: "expired-waiver"}},
	}
	n, err := SweepExpiredWaivers(context.Background(), store, slog.Default())
	requireNoError(t, err)
	assert.Equal(t, 1, n)

	store.err = assertAnError("db down")
	_, err = SweepExpiredWaivers(context.Background(), store, slog.Default())
	assert.ErrorContains(t, err, "db down")
}

func TestRunWaiverExpiry_CancellationStops(t *testing.T) {
	store := &fakeWaiverExpiryStore{expired: []port.Waiver{{ID: "w1"}}}
	ctx, cancel := context.WithCancel(context.Background())

	RunWaiverExpiry(ctx, store, nil, time.Hour, 10*time.Millisecond, slog.Default())
	time.Sleep(50 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)

	assert.GreaterOrEqual(t, store.calls.Load(), int64(1), "ticker should have fired before cancellation")
}

func requireNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func assertAnError(msg string) error { return errString(msg) }
