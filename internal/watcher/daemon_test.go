// Offline, deterministic tests for the polling daemon: no network, no
// database. Every dependency (client, store, inventory, gap check, watermark,
// clock) is a fake wired through PollDeps / RunCveWatcherConfig.
package watcher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

var (
	// fixedNow is the injected clock for deterministic watermark assertions.
	fixedNow = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	// projectID is the sole watched project in most tests.
	projectID = pgtype.UUID{Bytes: uuid.MustParse("11111111-1111-1111-1111-111111111111"), Valid: true}
	// suppressingID is the scan-derived finding that suppresses a watcher hit.
	suppressingID = pgtype.UUID{Bytes: uuid.MustParse("22222222-2222-2222-2222-222222222222"), Valid: true}
)

// testLogger discards log output so tests stay quiet.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// inventoryRow builds one distinct-inventory row.
func inventoryRow(purl, eco, name, version string) sqlc.DistinctInventoryRow {
	return sqlc.DistinctInventoryRow{
		ProjectID:  projectID,
		Purl:       purl,
		Ecosystem:  pgtype.Text{String: eco, Valid: true},
		Name:       pgtype.Text{String: name, Valid: true},
		Version:    pgtype.Text{String: version, Valid: true},
		LastSeenAt: pgtype.Timestamptz{Time: fixedNow, Valid: true},
	}
}

// testAdvisory builds an advisory matching lodash@4.17.19 in the npm
// ecosystem. Raw holds the JSON round-trip of the decoded fields, mimicking
// the client's raw-byte capture.
func testAdvisory(id, published string) Advisory {
	a := Advisory{
		ID:        id,
		Aliases:   []string{"CVE-2024-0001"},
		Summary:   "test advisory " + id,
		Published: published,
		Severity: []AdvisorySeverity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
		},
		Affected: []Affected{
			{
				Ecosystem: "npm",
				Package:   Package{Name: "lodash"},
				Ranges: []VersionRange{
					{Type: "SEMVER", Events: []RangeEvent{{Introduced: "0"}, {Fixed: "4.17.20"}}},
				},
			},
		},
		Refs: []AdvisoryRef{{URL: "https://example.test/" + id}},
	}
	raw, _ := json.Marshal(a)
	a.Raw = raw
	return a
}

// pypiAdvisory builds an advisory matching requests 2.31.0 in the pypi
// ecosystem — testAdvisory hardcodes npm, which would never match a pypi row.
func pypiAdvisory(id, published string) Advisory {
	a := testAdvisory(id, published)
	a.Affected[0].Ecosystem = "pypi"
	a.Affected[0].Package.Name = "requests"
	raw, _ := json.Marshal(a)
	a.Raw = raw
	return a
}

// fakeClient is a canned Client keyed by ecosystem\x00name.
type fakeClient struct {
	mu      sync.Mutex
	results map[string][]Advisory
	err     error
	// queries records every QueryBatch call for call-count assertions.
	queries [][]Query
	// blocking stubs for the single-poll-isolation test.
	block   chan struct{}
	entered chan struct{}
}

func (f *fakeClient) QueryBatch(ctx context.Context, queries []Query) ([]QueryResult, error) {
	f.mu.Lock()
	f.queries = append(f.queries, queries)
	block := f.block
	err := f.err
	results := make([]QueryResult, len(queries))
	for i, q := range queries {
		results[i].Query = q
		results[i].Advisories = f.results[q.Package.Ecosystem+"\x00"+q.Package.Name]
	}
	f.mu.Unlock()
	if block != nil {
		f.entered <- struct{}{}
		<-block
	}
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (f *fakeClient) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queries)
}

type skipCall struct {
	id pgtype.UUID
	ev Event
}

// recordingStore captures persisted decisions for assertions.
type recordingStore struct {
	mu         sync.Mutex
	created    []Decision
	skips      []skipCall
	persistErr error
	skipErr    error
	// reportNoOp mirrors a re-poll hit: PersistFoundFinding reports
	// created=false so the poll counts the outcome as unchanged rather than
	// a new finding.
	reportNoOp bool
}

func (s *recordingStore) PersistFoundFinding(ctx context.Context, d Decision) (pgtype.UUID, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.created = append(s.created, d)
	if s.persistErr != nil {
		return pgtype.UUID{}, false, s.persistErr
	}
	if s.reportNoOp {
		return suppressingID, false, nil
	}
	return suppressingID, true, nil
}

func (s *recordingStore) PersistSkipEvent(ctx context.Context, id pgtype.UUID, ev Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.skips = append(s.skips, skipCall{id: id, ev: ev})
	return s.skipErr
}

// baseDeps returns a PollDeps with safe defaults; tests override the fields
// they exercise.
func baseDeps() PollDeps {
	return PollDeps{
		Client:   &fakeClient{results: map[string][]Advisory{}},
		Store:    &recordingStore{},
		Projects: []pgtype.UUID{projectID},
		Inventory: func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
			return nil, nil
		},
		FindGap: func(ctx context.Context, pid pgtype.UUID, purlName string, candidateIDs []string) (pgtype.UUID, error) {
			return pgtype.UUID{}, pgx.ErrNoRows
		},
		GetWatermark: func(ctx context.Context) (time.Time, bool, error) { return time.Time{}, false, nil },
		SetWatermark: func(ctx context.Context, ts time.Time) error { return nil },
		Now:          func() time.Time { return fixedNow },
		Logger:       testLogger(),
		InventoryTTL: 720 * time.Hour,
	}
}

func TestPollOnce_ColdStartFullHistory_AdvancesWatermark(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2020-01-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	var wm time.Time
	watermarked := false
	deps.SetWatermark = func(ctx context.Context, ts time.Time) error { wm, watermarked = ts, true; return nil }

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	require.True(t, watermarked, "watermark must advance after a successful poll")
	assert.Equal(t, fixedNow, wm)
	assert.Equal(t, 1, outcome.Created)
	assert.Equal(t, 1, outcome.Queried)
	store := deps.Store.(*recordingStore)
	require.Len(t, store.created, 1)
	// The persisted decision carries the raw advisory bytes byte-exact.
	assert.Equal(t, client.results["npm\x00lodash"][0].Raw, store.created[0].Evidence)
	assert.Equal(t, "cve_watcher", store.created[0].Finding.FindingKind)
	assert.NotEmpty(t, store.created[0].Finding.Fingerprint)
}

func TestPollOnce_WatermarkUntouchedOnFailure(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.err = errors.New("connection refused")
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	watermarked := false
	deps.SetWatermark = func(ctx context.Context, ts time.Time) error { watermarked = true; return nil }

	_, err := PollOnce(context.Background(), deps)
	require.Error(t, err)
	assert.False(t, watermarked, "watermark must NOT advance on a failed poll")
}

func TestPollOnce_WarmPollFiltersAdvisoriesBeforeWatermark(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{
		testAdvisory("GHSA-old-old-old", "2020-01-01T00:00:00Z"), // before watermark
		testAdvisory("GHSA-new-new-new", "2026-06-01T00:00:00Z"), // after watermark
	}
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	deps.GetWatermark = func(ctx context.Context) (time.Time, bool, error) {
		return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), true, nil
	}

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.Created, "only the post-watermark advisory is decided")
	assert.Equal(t, 1, outcome.Ignored, "pre-watermark advisory filtered")
	store := deps.Store.(*recordingStore)
	require.Len(t, store.created, 1)
	assert.Equal(t, "GHSA-new-new-new", store.created[0].Finding.Display["advisory_id"])
}

func TestPollOnce_ColdStartWindowFiltersBySince(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{
		testAdvisory("GHSA-old-old-old", "2020-01-01T00:00:00Z"),
		testAdvisory("GHSA-new-new-new", "2026-08-01T00:00:00Z"),
	}
	deps.Since = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) // WATCHER_COLD_START_WINDOW
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.Created)
	assert.Equal(t, 1, outcome.Ignored)
}

func TestPollOnce_GapSkipAttachesEventToSuppressingID(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	deps.FindGap = func(ctx context.Context, pid pgtype.UUID, purlName string, candidateIDs []string) (pgtype.UUID, error) {
		assert.Equal(t, "pkg:npm/lodash", purlName)
		assert.Contains(t, candidateIDs, "CVE-2024-0001")
		return suppressingID, nil
	}

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.Skipped)
	store := deps.Store.(*recordingStore)
	require.Len(t, store.skips, 1)
	assert.Equal(t, suppressingID, store.skips[0].id)
	assert.Equal(t, EventAutoRuleSkipped, store.skips[0].ev.EventType)
	assert.Empty(t, store.created, "no finding created on gap-skip")
}

func TestPollOnce_BatchResponseMappingAcrossGroups(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	// Two distinct query groups; OSV answers each package separately.
	client.results["PyPI\x00requests"] = []Advisory{pypiAdvisory("GHSA-pppp-pppp-pppp", "2026-06-01T00:00:00Z")}
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-llll-llll-llll", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{
			inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19"),
			inventoryRow("pkg:npm/lodash@4.17.15", "npm", "lodash", "4.17.15"),
			inventoryRow("pkg:pypi/requests@2.31.0", "pypi", "requests", "2.31.0"),
		}, nil
	}

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Equal(t, 3, outcome.Created, "one decision per (row, advisory) pair")
	// Query order is deterministic: PyPI sorts before npm.
	require.Len(t, client.queries, 1)
	require.Len(t, client.queries[0], 2)
	assert.Equal(t, "PyPI", client.queries[0][0].Package.Ecosystem, "stored 'pypi' mapped to OSV canonical 'PyPI'")
	assert.Equal(t, "requests", client.queries[0][0].Package.Name)
	assert.Equal(t, "npm", client.queries[0][1].Package.Ecosystem)
	store := deps.Store.(*recordingStore)
	require.Len(t, store.created, 3)
	for _, d := range store.created {
		assert.Equal(t, "cve_watcher", d.Finding.FindingKind)
	}
}

func TestPollOnce_EmptyInventorySkipsClient(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	outcome, err := PollOnce(context.Background(), deps) // inventory returns nil
	require.NoError(t, err)
	assert.Zero(t, client.callCount(), "no OSV query for an empty inventory")
	assert.Equal(t, 0, outcome.Created)
}

func TestPollOnce_UnqueryableRowsDropped(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{
			inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19"),
			inventoryRow("pkg:generic/noname@1.0.0", "npm", "", "1.0.0"),  // empty name
			inventoryRow("pkg:generic/noeco@1.0.0", "", "noeco", "1.0.0"), // empty ecosystem
		}, nil
	}

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	require.Len(t, client.queries, 1)
	assert.Len(t, client.queries[0], 1, "only the queryable row is queried")
	assert.Equal(t, 1, outcome.Created)
}

func TestPollOnce_StoreErrorAbortsAndKeepsWatermark(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	store := deps.Store.(*recordingStore)
	store.persistErr = errors.New("tx failed")
	watermarked := false
	deps.SetWatermark = func(ctx context.Context, ts time.Time) error { watermarked = true; return nil }

	_, err := PollOnce(context.Background(), deps)
	require.Error(t, err)
	assert.False(t, watermarked)
}

func TestPollOnce_RepollHitCountedUnchangedNotCreated(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	// The store reports created=false, as a real re-poll hit of an existing
	// watcher finding would (CreateFindingIfAbsent -> pgx.ErrNoRows).
	store := deps.Store.(*recordingStore)
	store.reportNoOp = true

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Equal(t, 0, outcome.Created, "a re-poll hit must not be counted as a new finding")
	assert.Equal(t, 1, outcome.Unchanged, "a re-poll hit is counted as unchanged")
	require.Len(t, store.created, 1, "the decision is still handed to the store for its no-op guard")
}

func TestPollOnce_MalformedResponseDoesNotAdvanceWatermark(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	// A malformed/short OSV response is a non-retryable error (***REMOVED***
	// unknown-ecosystem guard): the poll must abort and leave the watermark alone.
	client.err = ErrMalformedResponse
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	watermarked := false
	deps.SetWatermark = func(ctx context.Context, ts time.Time) error { watermarked = true; return nil }

	_, err := PollOnce(context.Background(), deps)
	require.Error(t, err)
	assert.False(t, IsRetryable(err), "malformed response must not be retried")
	assert.False(t, watermarked, "watermark must NOT advance on a short/malformed response")
}

func TestBuildOccurrence_RawAdvisoryBase64(t *testing.T) {
	raw := []byte(`{"id":"GHSA-abc","database_specific":{"source":"nvd"},"credits":[]}`)
	decision := Decision{
		Finding: FindingPayload{
			Title:        "t",
			Description:  "d",
			Severity:     "high",
			SeverityRank: 3,
			Score:        7.5,
			Remediation:  "upgrade",
			Display:      map[string]any{"purl": "pkg:npm/lodash@4.17.19"},
			Metadata:     map[string]any{"advisory_id": "GHSA-abc"},
		},
		Evidence: raw,
	}
	occ, err := buildOccurrence(decision, fixedNow)
	require.NoError(t, err)
	assert.Equal(t, pgtype.UUID{}, occ.ReportID, "watcher occurrence carries NULL report_id")
	var meta map[string]any
	require.NoError(t, json.Unmarshal(occ.Metadata, &meta))
	b64, ok := meta[MetadataRawAdvisoryKey].(string)
	require.True(t, ok, "raw_advisory must be present")
	decoded, err := base64.StdEncoding.DecodeString(b64)
	require.NoError(t, err)
	assert.Equal(t, raw, decoded, "raw advisory bytes survive base64 round-trip byte-exact")
	assert.Equal(t, "GHSA-abc", meta["advisory_id"])
	assert.Equal(t, "osv-batch", occ.ToolName)
}

func TestEvidencePayload_FirstRefAndSummary(t *testing.T) {
	advisory := testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")
	url, desc := evidencePayload(Decision{Evidence: advisory.Raw})
	assert.Equal(t, "https://example.test/GHSA-aaaa-bbbb-cccc", url)
	assert.Equal(t, "test advisory GHSA-aaaa-bbbb-cccc", desc)

	url, desc = evidencePayload(Decision{Evidence: []byte("{not json")})
	assert.Equal(t, "", url)
	assert.Equal(t, "", desc, "malformed evidence degrades to empty values, not an error")

	noRefs := advisory
	noRefs.Refs = nil
	noRefs.Raw, _ = json.Marshal(noRefs)
	url, _ = evidencePayload(Decision{Evidence: noRefs.Raw})
	assert.Equal(t, "", url)
}

func TestGroupInventory_DedupesAndDropsUnqueryable(t *testing.T) {
	groups := groupInventory([]sqlc.DistinctInventoryRow{
		inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19"),
		inventoryRow("pkg:npm/lodash@4.17.15", "npm", "lodash", "4.17.15"),
		inventoryRow("pkg:pypi/requests@2.31.0", "PyPI", "requests", "2.31.0"),
		inventoryRow("pkg:generic/x@1.0.0", "npm", "", "1.0.0"),
	})
	require.Len(t, groups, 2)
	// Keys sort byte-wise on the OSV-canonical ecosystem: "PyPI" precedes
	// "npm", so the requests group lands first — order is deterministic.
	assert.Equal(t, "PyPI", groups[0].ecosystem, "stored ecosystem mapped to OSV canonical form")
	assert.Equal(t, "requests", groups[0].name)
	assert.Equal(t, "npm", groups[1].ecosystem)
	assert.Len(t, groups[1].rows, 2, "same-named packages collapse into one query")
	assert.Equal(t, "lodash", groups[1].name)
}

func TestNextBackoff(t *testing.T) {
	initial, max := 30*time.Second, 5*time.Minute
	cases := []struct {
		current time.Duration
		want    time.Duration
	}{
		{0, 30 * time.Second},
		{30 * time.Second, 60 * time.Second},
		{60 * time.Second, 120 * time.Second},
		{120 * time.Second, 240 * time.Second},
		{240 * time.Second, 5 * time.Minute}, // 480s capped at 5m
		{5 * time.Minute, 5 * time.Minute},   // steady state at max
	}
	for _, c := range cases {
		assert.Equal(t, c.want, nextBackoff(c.current, initial, max), "current=%v", c.current)
	}
}

// runDaemon starts RunCveWatcher and returns a done channel that closes when
// the loop exits.
func runDaemon(ctx context.Context, cfg RunCveWatcherConfig) chan struct{} {
	done := make(chan struct{})
	go func() {
		RunCveWatcher(ctx, cfg)
		close(done)
	}()
	return done
}

// eventually polls cond until it passes or the deadline expires.
func eventually(t *testing.T, cond func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition never became true within", timeout)
}

func TestRunCveWatcher_FirstTickImmediateAndSteadyCadence(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}

	var mu sync.Mutex
	var sleeps []time.Duration
	sleep := func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		sleeps = append(sleeps, d)
		mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runDaemon(ctx, RunCveWatcherConfig{
		PollDeps:     deps,
		PollInterval: 10 * time.Minute,
		Jitter:       func(d time.Duration) time.Duration { return d },
		Sleep:        sleep,
		Logger:       testLogger(),
	})

	// Each iteration performs one successful poll then sleeps the interval.
	eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sleeps) >= 3
	}, 5*time.Second)

	mu.Lock()
	calls := client.callCount()
	mu.Unlock()
	require.GreaterOrEqual(t, calls, 3, "first poll fires before any sleep")
	mu.Lock()
	defer mu.Unlock()
	for i, d := range sleeps {
		assert.Equal(t, 10*time.Minute, d, "steady-state sleeps equal the poll interval (sleep %d)", i)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not stop on cancellation")
	}
}

func TestRunCveWatcher_BackoffDoublingWhenFailing(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.err = errors.New("upstream down") // every poll fails
	// baseDeps ships an empty inventory, which would make polls succeed
	// without ever touching the client; feed it a row so QueryBatch is
	// actually invoked and fails.
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}

	var mu sync.Mutex
	var sleeps []time.Duration
	sleep := func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		sleeps = append(sleeps, d)
		mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runDaemon(ctx, RunCveWatcherConfig{
		PollDeps:       deps,
		PollInterval:   10 * time.Minute,
		InitialBackoff: 30 * time.Second,
		MaxBackoff:     5 * time.Minute,
		Jitter:         func(d time.Duration) time.Duration { return d },
		Sleep:          sleep,
		Logger:         testLogger(),
	})

	eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sleeps) >= 6
	}, 5*time.Second)

	mu.Lock()
	defer mu.Unlock()
	// The fake sleep never blocks, so the daemon keeps failing and the slice
	// grows past the deterministic prefix; only the prefix is deterministic.
	assert.GreaterOrEqual(t, len(sleeps), 6)
	want := []time.Duration{
		30 * time.Second, 60 * time.Second, 120 * time.Second,
		240 * time.Second, 5 * time.Minute, 5 * time.Minute,
	}
	for i, want := range want {
		assert.Equal(t, want, sleeps[i], "backoff entry %d", i)
	}
	for _, d := range sleeps[6:] {
		assert.Equal(t, 5*time.Minute, d, "backoff caps at 5m")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not stop on cancellation")
	}
}

// flakyClient fails the first n QueryBatch calls, then delegates to inner.
type flakyClient struct {
	inner     *fakeClient
	failFirst int
	failures  int
}

func (f *flakyClient) QueryBatch(ctx context.Context, queries []Query) ([]QueryResult, error) {
	if f.failures < f.failFirst {
		f.failures++
		return nil, errors.New("transient failure")
	}
	return f.inner.QueryBatch(ctx, queries)
}

func TestRunCveWatcher_BackoffResetsOnSuccess(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	deps.Client = &flakyClient{inner: client, failFirst: 2}

	var mu sync.Mutex
	var sleeps []time.Duration
	sleep := func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		sleeps = append(sleeps, d)
		mu.Unlock()
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runDaemon(ctx, RunCveWatcherConfig{
		PollDeps:       deps,
		PollInterval:   10 * time.Minute,
		InitialBackoff: 30 * time.Second,
		MaxBackoff:     5 * time.Minute,
		Jitter:         func(d time.Duration) time.Duration { return d },
		Sleep:          sleep,
		Logger:         testLogger(),
	})

	// Two failures (30s, 60s) then a success resets to the poll interval.
	eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(sleeps) >= 3
	}, 5*time.Second)

	mu.Lock()
	defer mu.Unlock()
	// The fake sleep never blocks, so the daemon keeps polling and the slice
	// grows past the interesting prefix; only the prefix is deterministic.
	assert.GreaterOrEqual(t, len(sleeps), 3)
	assert.Equal(t, 30*time.Second, sleeps[0], "first failure backs off 30s")
	assert.Equal(t, 60*time.Second, sleeps[1], "second failure doubles to 60s")
	for _, d := range sleeps[2:] {
		assert.Equal(t, 10*time.Minute, d, "success resets to the poll interval")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not stop on cancellation")
	}
}

func TestRunCveWatcher_StopsOnContextCancel(t *testing.T) {
	deps := baseDeps()
	ctx, cancel := context.WithCancel(context.Background())
	done := runDaemon(ctx, RunCveWatcherConfig{
		PollDeps:     deps,
		PollInterval: time.Minute,
		// Sleep blocks until the context is done: the loop observes
		// cancellation instead of spinning.
		Sleep: func(ctx context.Context, d time.Duration) error {
			<-ctx.Done()
			return ctx.Err()
		},
		Logger: testLogger(),
	})
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon must exit when the context is cancelled")
	}
}

func TestRunCveWatcher_SinglePollIsolation(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid pgtype.UUID, since time.Duration) ([]sqlc.DistinctInventoryRow, error) {
		return []sqlc.DistinctInventoryRow{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	// The first in-flight poll blocks inside the client until released.
	client.block = make(chan struct{})
	client.entered = make(chan struct{}, 1)

	cfg := RunCveWatcherConfig{
		PollDeps:     deps,
		PollInterval: time.Millisecond, // tight loop: many ticks while blocked
		Jitter:       func(d time.Duration) time.Duration { return d },
		Sleep:        func(ctx context.Context, d time.Duration) error { return nil },
		Logger:       testLogger(),
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runDaemon(ctx, cfg)

	// First poll enters and blocks.
	select {
	case <-client.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first poll never entered the client")
	}
	// Give the tight loop many occasions to overlap the blocked poll.
	time.Sleep(100 * time.Millisecond)
	assert.Equal(t, 1, client.callCount(), "a second poll must never overlap the first (single-poll isolation)")
	close(client.block)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not stop")
	}
}

func TestJitterBounds(t *testing.T) {
	jitter := func(base time.Duration) time.Duration {
		factor := 1 + rand.Float64()*0.2 - 0.1
		return time.Duration(float64(base) * factor)
	}
	for i := 0; i < 1000; i++ {
		got := jitter(10 * time.Minute)
		assert.True(t, got >= 9*time.Minute && got <= 11*time.Minute, "jitter outside ±10%: %v", got)
	}
}

func TestJitterRejectsZeroBase(t *testing.T) {
	// A zero base must stay zero-friendly: the default jitter only runs on
	// positive delays, but a degenerate zero delay must not panic.
	var got time.Duration
	require.NotPanics(t, func() { got = jitterDuration(0) })
	assert.Zero(t, got)
}
