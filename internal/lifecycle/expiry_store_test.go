package lifecycle

import (
	"context"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/xMinhx/specht/internal/port"
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

	RunWaiverExpiry(ctx, store, 10*time.Millisecond, slog.Default())
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
