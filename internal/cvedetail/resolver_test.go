package cvedetail

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *testClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *testClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newTestResolver(store Store, clock *testClock, providers ...Provider) *Resolver {
	return NewResolver(store, Config{
		Now:       clock.Now,
		Logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		Rates:     map[string]float64{"a": 1000, "b": 1000, "c": 1000},
		QueueSize: 4,
	}, providers...)
}

func sampleRecord(cve string) Record {
	return Record{CVEID: cve, CVSS: []CVSSRecord{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 9.8}}, CWEs: []string{"CWE-79"}}
}

func TestResolver_StopsAtFirstFoundAndCachesNegatives(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	store := newMemStore()
	a, b, c := NewFake("a"), NewFake("b"), NewFake("c")
	b.Set(sampleRecord(testCVE))
	c.Set(sampleRecord(testCVE))
	r := newTestResolver(store, clock, a, b, c)

	r.process(context.Background(), testCVE)
	assert.Equal(t, []string{testCVE}, a.Calls())
	assert.Equal(t, []string{testCVE}, b.Calls())
	assert.Empty(t, c.Calls(), "providers after the first found are not asked")

	na, ok := store.row("a", testCVE)
	require.True(t, ok)
	assert.Equal(t, StatusNotFound, na.Status)
	assert.Equal(t, clock.Now().Add(DefaultNegativeTTL), na.ExpiresAt)
	fb, ok := store.row("b", testCVE)
	require.True(t, ok)
	assert.Equal(t, StatusFound, fb.Status)
	assert.Equal(t, clock.Now().Add(DefaultTTL), fb.ExpiresAt)
	assert.Nil(t, fb.LeaseUntil)

	r.process(context.Background(), testCVE)
	assert.Len(t, a.Calls(), 1, "a fresh negative answer is reused")
	assert.Len(t, b.Calls(), 1, "a fresh answer is reused")

	clock.Advance(DefaultNegativeTTL + time.Minute)
	r.process(context.Background(), testCVE)
	assert.Len(t, a.Calls(), 2, "an expired negative answer is asked again")
	assert.Len(t, b.Calls(), 1, "the found answer is still fresh")
}

func TestResolver_LeaseHeldElsewhereMeansNoFetch(t *testing.T) {
	clock := &testClock{now: time.Now()}
	store := newMemStore()
	store.denyAll = true
	a := NewFake("a")
	r := newTestResolver(store, clock, a)
	r.process(context.Background(), testCVE)
	assert.Empty(t, a.Calls(), "another replica holds the lease, so this one does not fetch")
}

func TestResolver_ConcurrentProcessFetchesOnce(t *testing.T) {
	clock := &testClock{now: time.Now()}
	store := newMemStore()
	a := NewFake("a")
	a.Set(sampleRecord(testCVE))
	release := a.Block()
	r1 := newTestResolver(store, clock, a)
	r2 := newTestResolver(store, clock, a)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); r1.process(context.Background(), testCVE) }()
	go func() { defer wg.Done(); r2.process(context.Background(), testCVE) }()
	require.Eventually(t, func() bool { return len(a.Calls()) >= 1 }, time.Second, time.Millisecond)
	time.Sleep(20 * time.Millisecond)
	release()
	wg.Wait()
	assert.Len(t, a.Calls(), 1, "two replicas share one lease, so the provider is asked once")
	assert.Equal(t, 1, store.leases)
}

func TestResolver_RateLimitBacksOffProviderAcrossCVEs(t *testing.T) {
	clock := &testClock{now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	store := newMemStore()
	a, b := NewFake("a"), NewFake("b")
	a.Fail(testCVE, &RateLimitedError{RetryAfter: 90 * time.Second})
	b.Set(sampleRecord("CVE-2024-0002"))
	r := newTestResolver(store, clock, a, b)

	r.process(context.Background(), testCVE)
	states, _ := store.ListProviderStates(context.Background())
	var aState ProviderState
	for _, s := range states {
		if s.Provider == "a" {
			aState = s
		}
	}
	assert.Equal(t, ErrKindRateLimited, aState.LastError)
	require.NotNil(t, aState.BackoffUntil)
	assert.Equal(t, clock.Now().Add(90*time.Second), *aState.BackoffUntil)
	_, placeholder := store.row("a", testCVE)
	assert.False(t, placeholder, "the failed first fetch leaves no row")
	assert.Len(t, b.Calls(), 1, "the next provider is still asked")
	assert.False(t, r.Schedule(testCVE), "a CVE whose fetch failed waits out its backoff")

	r.process(context.Background(), "CVE-2024-0002")
	assert.Len(t, a.Calls(), 1, "a provider under a rate-limit backoff is skipped for every CVE")

	clock.Advance(91 * time.Second)
	r.process(context.Background(), "CVE-2024-0003")
	assert.Len(t, a.Calls(), 2, "after the backoff the provider is asked again")
}

func TestResolver_BoundsRecordsBeforeCaching(t *testing.T) {
	clock := &testClock{now: time.Now()}
	store := newMemStore()
	a := NewFake("a")
	rec := Record{CVEID: testCVE}
	for range maxRecordCVSS {
		rec.CVSS = append(rec.CVSS, CVSSRecord{Version: "3.1", Vector: "CVSS:3.1/" + strings.Repeat("A", 200), Source: strings.Repeat("s", 5000)})
	}
	for i := range maxRecordReferences {
		rec.References = append(rec.References, "https://example.com/"+strings.Repeat("r", 2000)+string(rune('a'+i)))
	}
	a.Set(rec)
	raw, _ := json.Marshal(normalize(rec))
	require.Less(t, len(raw), MaxRecordBytes, "normalize already bounds a record under the cap")

	r := newTestResolver(store, clock, a)
	r.process(context.Background(), testCVE)
	e, ok := store.row("a", testCVE)
	require.True(t, ok)
	assert.Equal(t, StatusFound, e.Status)
	require.Len(t, e.Record.CVSS, maxRecordCVSS)
	for _, c := range e.Record.CVSS {
		assert.Len(t, c.Source, maxSourceLen, "sources are truncated")
	}
}

func TestResolver_QueueOverflowDrops(t *testing.T) {
	clock := &testClock{now: time.Now()}
	r := newTestResolver(newMemStore(), clock, NewFake("a"))
	for i, cve := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003", "CVE-2024-0004"} {
		assert.True(t, r.Schedule(cve), "job %d fits the queue", i)
	}
	assert.True(t, r.Schedule("CVE-2024-0001"), "a queued CVE is not queued twice")
	assert.False(t, r.Schedule("CVE-2024-0005"), "a full queue drops the job")
	assert.False(t, r.Schedule("not-a-cve"), "only CVE identifiers are queued")
}

func TestResolver_PrunesRetryMap(t *testing.T) {
	clock := &testClock{now: time.Now()}
	store := newMemStore()
	a := NewFake("a")
	for _, cve := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"} {
		a.Fail(cve, errors.New("boom"))
	}
	r := newTestResolver(store, clock, a)
	for _, cve := range []string{"CVE-2024-0001", "CVE-2024-0002", "CVE-2024-0003"} {
		store.states = map[string]ProviderState{}
		r.process(context.Background(), cve)
	}
	assert.Equal(t, 3, r.retryLen())
	clock.Advance(DefaultErrorBackoff + time.Second)
	r.Schedule("CVE-2024-0009")
	assert.Equal(t, 0, r.retryLen(), "entries past their backoff are pruned")
}

func TestResolver_LookupStatuses(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{now: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	store := newMemStore()
	a, b, c := NewFake("a"), NewFake("b"), NewFake("c")
	b.Set(sampleRecord(testCVE))
	r := newTestResolver(store, clock, a, b, c)

	got, err := r.Lookup(ctx, testCVE, false)
	require.NoError(t, err)
	assert.Equal(t, []string{LookupSkipped, LookupSkipped, LookupSkipped}, statuses(got), "a complete report consults no provider")
	assert.False(t, r.isQueued(testCVE))

	got, err = r.Lookup(ctx, testCVE, true)
	require.NoError(t, err)
	assert.Equal(t, []string{LookupPending, LookupPending, LookupPending}, statuses(got))
	assert.True(t, r.isQueued(testCVE), "an incomplete report schedules a fetch")

	r.process(ctx, testCVE)
	r.mu.Lock()
	delete(r.queued, testCVE)
	r.mu.Unlock()
	got, err = r.Lookup(ctx, testCVE, true)
	require.NoError(t, err)
	assert.Equal(t, []string{LookupNotFound, LookupFound, LookupSkipped}, statuses(got))
	require.NotNil(t, got[1].Record)
	require.NotNil(t, got[1].FetchedAt)
	assert.Equal(t, clock.Now(), *got[1].FetchedAt)
	assert.False(t, r.isQueued(testCVE), "fresh answers need no fetch")

	clock.Advance(DefaultTTL + time.Hour)
	got, err = r.Lookup(ctx, testCVE, true)
	require.NoError(t, err)
	assert.Equal(t, LookupFound, got[1].Status, "an expired answer is still served while it is refetched")
	assert.True(t, r.isQueued(testCVE))
}

func TestResolver_LookupReportsErrorDuringBackoff(t *testing.T) {
	ctx := context.Background()
	clock := &testClock{now: time.Now()}
	a := NewFake("a")
	a.Fail(testCVE, &HTTPStatusError{Code: 500})
	r := newTestResolver(newMemStore(), clock, a)
	r.process(ctx, testCVE)
	got, err := r.Lookup(ctx, testCVE, true)
	require.NoError(t, err)
	assert.Equal(t, []string{LookupError}, statuses(got))
}

func TestResolver_StartFetchesInBackground(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	clock := &testClock{now: time.Now()}
	a := NewFake("a")
	a.Set(sampleRecord(testCVE))
	r := newTestResolver(newMemStore(), clock, a)
	r.Start(ctx)

	got, err := r.Lookup(context.Background(), testCVE, true)
	require.NoError(t, err)
	assert.Equal(t, LookupPending, got[0].Status)
	require.Eventually(t, func() bool {
		got, err := r.Lookup(context.Background(), testCVE, true)
		return err == nil && got[0].Status == LookupFound
	}, 2*time.Second, 5*time.Millisecond)
	cancel()
	r.Wait()
}

func TestResolver_DisabledHasNoLookupAndListsEveryProviderOff(t *testing.T) {
	var r *Resolver
	got, err := r.Lookup(context.Background(), testCVE, true)
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.False(t, r.Schedule(testCVE))
	status, err := r.Status(context.Background())
	require.NoError(t, err)
	require.Len(t, status, len(KnownProviders))
	for _, s := range status {
		assert.False(t, s.Enabled)
	}
}

func TestResolver_StatusShowsKeyPresenceOnly(t *testing.T) {
	const key = "SENTINEL-KEY-status"
	store := newMemStore()
	now := time.Now().UTC()
	require.NoError(t, store.RecordError(context.Background(), ProviderNVD, ErrKindTimeout, now, now))
	r := NewResolver(store, Config{}, &NVD{APIKey: key}, &OSV{})
	status, err := r.Status(context.Background())
	require.NoError(t, err)
	require.Len(t, status, 3)
	assert.Equal(t, ProviderNVD, status[0].Name)
	assert.True(t, status[0].Enabled)
	assert.True(t, status[0].KeyConfigured)
	require.NotNil(t, status[0].LastError)
	assert.Equal(t, ErrKindTimeout, *status[0].LastError)
	assert.Equal(t, ProviderOSV, status[1].Name)
	assert.False(t, status[1].KeyConfigured)
	assert.Equal(t, ProviderVulnCheck, status[2].Name)
	assert.False(t, status[2].Enabled)
	raw, err := json.Marshal(status)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), key)
}

func TestSweepOnceUsesThirtyDayRetention(t *testing.T) {
	store := newMemStore()
	now := time.Now()
	_ = store.StoreAnswer(context.Background(), CacheEntry{Provider: "a", CVEID: "CVE-2024-0001", Status: StatusNotFound, ExpiresAt: now.Add(-31 * 24 * time.Hour)})
	_ = store.StoreAnswer(context.Background(), CacheEntry{Provider: "a", CVEID: "CVE-2024-0002", Status: StatusNotFound, ExpiresAt: now.Add(-29 * 24 * time.Hour)})
	n, err := SweepOnce(context.Background(), store, now)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
}

func statuses(in []ProviderLookup) []string {
	out := make([]string, len(in))
	for i, p := range in {
		out[i] = p.Status
	}
	return out
}
