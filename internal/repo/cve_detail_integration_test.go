//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/cvedetail"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const cveDetailTestCVE = "CVE-2024-3094"

func TestCVEDetailStore_LeaseIsSingleFlight(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	store := NewCVEDetailStore(repos.pool)
	now := time.Now().UTC().Truncate(time.Microsecond)

	got, err := store.AcquireLease(ctx, "nvd", cveDetailTestCVE, now, now.Add(time.Minute))
	require.NoError(t, err)
	require.True(t, got, "the first caller writes the placeholder and holds the lease")

	got, err = store.AcquireLease(ctx, "nvd", cveDetailTestCVE, now, now.Add(time.Minute))
	require.NoError(t, err)
	assert.False(t, got, "a second replica must not take a current lease")

	got, err = store.AcquireLease(ctx, "vulncheck", cveDetailTestCVE, now, now.Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, got, "leases are per provider")

	later := now.Add(2 * time.Minute)
	got, err = store.AcquireLease(ctx, "nvd", cveDetailTestCVE, later, later.Add(time.Minute))
	require.NoError(t, err)
	assert.True(t, got, "an expired lease can be taken over")

	entries, err := store.ListCached(ctx, cveDetailTestCVE)
	require.NoError(t, err)
	require.Len(t, entries, 2)
	for _, e := range entries {
		assert.Equal(t, cvedetail.StatusPending, e.Status)
		assert.Nil(t, e.Record)
		require.NotNil(t, e.LeaseUntil)
	}
}

func TestCVEDetailStore_AnswerReleasesLeaseAndBlocksRefetchUntilExpiry(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	store := NewCVEDetailStore(repos.pool)
	now := time.Now().UTC().Truncate(time.Microsecond)
	published := now.Add(-48 * time.Hour)

	got, err := store.AcquireLease(ctx, "nvd", cveDetailTestCVE, now, now.Add(time.Minute))
	require.NoError(t, err)
	require.True(t, got)
	rec := cvedetail.Record{
		CVEID:     cveDetailTestCVE,
		CVSS:      []cvedetail.CVSSRecord{{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", Score: 10, Source: "nvd@nist.gov", Type: "Primary"}},
		CWEs:      []string{"CWE-506"},
		Published: &published,
	}
	require.NoError(t, store.StoreAnswer(ctx, cvedetail.CacheEntry{
		Provider: "nvd", CVEID: cveDetailTestCVE, Status: cvedetail.StatusFound,
		Record: &rec, FetchedAt: now, ExpiresAt: now.Add(time.Hour),
	}))

	entries, err := store.ListCached(ctx, cveDetailTestCVE)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, cvedetail.StatusFound, entries[0].Status)
	assert.Nil(t, entries[0].LeaseUntil, "storing the answer releases the lease")
	require.NotNil(t, entries[0].Record)
	assert.Equal(t, rec.CVSS, entries[0].Record.CVSS)
	assert.Equal(t, []string{"CWE-506"}, entries[0].Record.CWEs)

	got, err = store.AcquireLease(ctx, "nvd", cveDetailTestCVE, now.Add(time.Minute), now.Add(2*time.Minute))
	require.NoError(t, err)
	assert.False(t, got, "a fresh answer is not refetched")

	got, err = store.AcquireLease(ctx, "nvd", cveDetailTestCVE, now.Add(2*time.Hour), now.Add(3*time.Hour))
	require.NoError(t, err)
	assert.True(t, got, "an expired answer may be refetched")
	entries, err = store.ListCached(ctx, cveDetailTestCVE)
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, cvedetail.StatusFound, entries[0].Status, "the stale answer stays while it is refetched")

	require.NoError(t, store.ReleaseLease(ctx, "nvd", cveDetailTestCVE))
	entries, err = store.ListCached(ctx, cveDetailTestCVE)
	require.NoError(t, err)
	require.Len(t, entries, 1, "releasing keeps a real answer")
	assert.Nil(t, entries[0].LeaseUntil)
}

func TestCVEDetailStore_ReleaseDropsPlaceholder(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	store := NewCVEDetailStore(repos.pool)
	now := time.Now().UTC()

	got, err := store.AcquireLease(ctx, "osv", cveDetailTestCVE, now, now.Add(time.Minute))
	require.NoError(t, err)
	require.True(t, got)
	require.NoError(t, store.ReleaseLease(ctx, "osv", cveDetailTestCVE))
	entries, err := store.ListCached(ctx, cveDetailTestCVE)
	require.NoError(t, err)
	assert.Empty(t, entries, "a failed first fetch leaves no row behind")
}

func TestCVEDetailStore_RejectsMalformedCVEAndOversizeRecord(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	store := NewCVEDetailStore(repos.pool)
	now := time.Now().UTC()

	_, err := store.AcquireLease(ctx, "nvd", "CVE-1'; DROP TABLE x", now, now.Add(time.Minute))
	require.Error(t, err, "the CHECK constraint refuses anything but a CVE identifier")

	big := cvedetail.Record{CVEID: cveDetailTestCVE}
	for range 2000 {
		big.References = append(big.References, "https://example.com/a/very/long/reference/path/that/repeats/many/times")
	}
	err = store.StoreAnswer(ctx, cvedetail.CacheEntry{Provider: "nvd", CVEID: cveDetailTestCVE, Status: cvedetail.StatusFound, Record: &big, FetchedAt: now, ExpiresAt: now.Add(time.Hour)})
	require.Error(t, err, "records over 64 KiB are refused before they reach the table")
}

func TestCVEDetailStore_SweepDeletesOnlyLongExpiredRows(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	store := NewCVEDetailStore(repos.pool)
	now := time.Now().UTC()

	old := now.Add(-40 * 24 * time.Hour)
	recent := now.Add(-2 * 24 * time.Hour)
	require.NoError(t, store.StoreAnswer(ctx, cvedetail.CacheEntry{Provider: "nvd", CVEID: "CVE-2020-0001", Status: cvedetail.StatusNotFound, FetchedAt: old, ExpiresAt: old.Add(time.Hour)}))
	require.NoError(t, store.StoreAnswer(ctx, cvedetail.CacheEntry{Provider: "nvd", CVEID: "CVE-2020-0002", Status: cvedetail.StatusNotFound, FetchedAt: recent, ExpiresAt: recent.Add(time.Hour)}))

	n, err := cvedetail.SweepOnce(ctx, store, now)
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	gone, err := store.ListCached(ctx, "CVE-2020-0001")
	require.NoError(t, err)
	assert.Empty(t, gone)
	kept, err := store.ListCached(ctx, "CVE-2020-0002")
	require.NoError(t, err)
	assert.Len(t, kept, 1, "a row expired for less than 30 days stays")
}

func TestCVEDetailStore_ProviderStatusKeepsTheLongerBackoff(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	store := NewCVEDetailStore(repos.pool)
	now := time.Now().UTC().Truncate(time.Microsecond)

	require.NoError(t, store.RecordSuccess(ctx, "nvd", now))
	require.NoError(t, store.RecordError(ctx, "nvd", cvedetail.ErrKindRateLimited, now, now.Add(time.Hour)))
	require.NoError(t, store.RecordError(ctx, "nvd", cvedetail.ErrKindTimeout, now.Add(time.Second), now.Add(time.Minute)))

	states, err := store.ListProviderStates(ctx)
	require.NoError(t, err)
	require.Len(t, states, 1)
	s := states[0]
	assert.Equal(t, "nvd", s.Provider)
	assert.Equal(t, cvedetail.ErrKindTimeout, s.LastError)
	require.NotNil(t, s.LastSuccessAt)
	assert.True(t, s.LastSuccessAt.Equal(now))
	require.NotNil(t, s.BackoffUntil)
	assert.True(t, s.BackoffUntil.Equal(now.Add(time.Hour)), "a later short backoff never shortens a rate-limit backoff")

	err = store.RecordError(ctx, "nvd", "Bearer secret-token", now, now)
	require.Error(t, err, "the CHECK constraint keeps free text out of last_error")
}

// TestCVEDetailStore_LatestOccurrencesIncludeWatcherFindings pins the read
// the CVE endpoint depends on: a watcher occurrence has no report, and an
// inner join on reports would hide it.
func TestCVEDetailStore_LatestOccurrencesIncludeWatcherFindings(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	stores := NewPortStores(pool)
	ctx := context.Background()

	creator, err := stores.Users.Create(ctx, "cve-detail-watcher@example.com", nil, nil)
	require.NoError(t, err)
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: scanner.NewRegistry()})
	_, err = uc.CreateProject(globalAdminCtx(creator.ID), "CVE detail watcher", "cve-detail-watcher", "validation", creator.ID)
	require.NoError(t, err)
	project, err := stores.Projects.GetBySlug(ctx, "cve-detail-watcher")
	require.NoError(t, err)

	source := "watcher"
	observed := time.Now().UTC().Truncate(time.Microsecond)
	f, err := stores.Findings.PersistWatcherFinding(ctx, port.PersistWatcherFindingInput{
		Finding: port.Finding{
			ProjectID: project.ID, FindingKind: "cve_watcher", Fingerprint: "sha256:cve-detail-watcher",
			CurrentTitle: "watcher finding", CurrentSeverity: "critical", CurrentSeverityRank: 40,
		},
		Dimensions: []port.DimensionInput{{Key: "vulnerability_id", Value: cveDetailTestCVE, Source: &source}},
		Occurrence: port.OccurrenceInput{
			Title: "watcher finding", Severity: "critical", SeverityRank: 40, ToolName: "osv-batch",
			Display: []byte("{}"), Metadata: []byte(`{"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}`),
			ObservedAt: observed,
		},
	})
	require.NoError(t, err)

	occ, err := NewCVEDetailStore(pool).ListLatestCVEOccurrences(ctx, f.ID)
	require.NoError(t, err)
	require.Len(t, occ, 1)
	assert.Equal(t, "osv-batch", occ[0].ToolName)
	assert.Nil(t, occ[0].ReportID)
	assert.True(t, occ[0].ObservedAt.Equal(observed))
	assert.JSONEq(t, `{"cvss_vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"}`, string(occ[0].Metadata))
}
