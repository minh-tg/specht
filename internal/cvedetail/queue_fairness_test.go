package cvedetail

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newQueueResolver(cfg Config) *Resolver {
	cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	return NewResolver(newMemStore(), cfg, NewFake("a"))
}

func queueCVE(base, i int) string { return fmt.Sprintf("CVE-2099-%05d", base+i) }

// One project cannot hold more than its share of the waiting jobs, so another
// project can still queue a fetch while the first keeps asking.
func TestLookupCapsQueuedJobsPerProject(t *testing.T) {
	r := newQueueResolver(Config{QueueSize: 16, MaxQueuedPerOwner: 3})
	greedy := WithOwner(context.Background(), "project-greedy")
	other := WithOwner(context.Background(), "project-other")

	for i := range 10 {
		_, err := r.Lookup(greedy, queueCVE(10000, i), true)
		require.NoError(t, err)
	}
	assert.Equal(t, 3, len(r.jobs), "the greedy project holds at most its share")

	victim := "CVE-2024-3094"
	got, err := r.Lookup(other, victim, true)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, LookupPending, got[0].Status)
	assert.True(t, r.isQueued(victim), "another project still gets its fetch queued")
}

// The share comes back when a worker takes a job, so a project that stayed
// within its cap is not locked out for good.
func TestQueuedShareIsReleasedWhenAWorkerTakesTheJob(t *testing.T) {
	r := newQueueResolver(Config{QueueSize: 16, MaxQueuedPerOwner: 2})
	ctx := WithOwner(context.Background(), "project-a")
	require.True(t, r.schedule(queueCVE(10000, 0), "project-a"))
	require.True(t, r.schedule(queueCVE(10000, 1), "project-a"))
	require.False(t, r.schedule(queueCVE(10000, 2), "project-a"), "at the cap")

	taken := <-r.jobs
	r.dequeued(taken)
	assert.True(t, r.schedule(queueCVE(10000, 2), "project-a"), "a freed slot can be used again")
	_, err := r.Lookup(ctx, queueCVE(10000, 3), true)
	require.NoError(t, err)
	assert.False(t, r.isQueued(queueCVE(10000, 3)), "the cap holds again")
}

// A CVE that is already queued costs the second project nothing and stays
// with the first.
func TestQueuedCVEIsSharedAcrossProjects(t *testing.T) {
	r := newQueueResolver(Config{QueueSize: 16, MaxQueuedPerOwner: 1})
	require.True(t, r.schedule("CVE-2024-3094", "project-a"))
	assert.True(t, r.schedule("CVE-2024-3094", "project-b"))
	assert.True(t, r.schedule("CVE-2024-0001", "project-b"), "project-b has its own share left")
}

// A read whose job was dropped because the queue is full must not say that a
// fetch is pending: nothing will run it, and a client would keep polling.
func TestLookupReportsErrorWhenTheQueueIsFull(t *testing.T) {
	store := newMemStore()
	nvd := NewFake(ProviderNVD)
	release := nvd.Block()
	defer release()
	r := NewResolver(store, Config{
		Logger:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		MaxQueuedPerOwner: 1000,
	}, nvd)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r.Start(ctx)

	for i := range DefaultQueueSize + DefaultWorkers + 10 {
		_, err := r.Lookup(ctx, queueCVE(10000, i), true)
		require.NoError(t, err)
	}
	time.Sleep(50 * time.Millisecond)
	for i := range 10 {
		_, _ = r.Lookup(ctx, queueCVE(20000, i), true)
	}
	require.Equal(t, cap(r.jobs), len(r.jobs), "queue is full")

	victim := "CVE-2024-3094"
	got, err := r.Lookup(ctx, victim, true)
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, LookupError, got[0].Status, "a dropped job is not reported as pending")
	assert.False(t, r.isQueued(victim))
}

// The same holds when the project share, not the whole queue, is used up.
func TestLookupReportsErrorWhenTheProjectShareIsUsedUp(t *testing.T) {
	r := newQueueResolver(Config{QueueSize: 16, MaxQueuedPerOwner: 1})
	ctx := WithOwner(context.Background(), "project-a")
	first, err := r.Lookup(ctx, queueCVE(10000, 0), true)
	require.NoError(t, err)
	assert.Equal(t, LookupPending, first[0].Status)

	second, err := r.Lookup(ctx, queueCVE(10000, 1), true)
	require.NoError(t, err)
	assert.Equal(t, LookupError, second[0].Status)
}
