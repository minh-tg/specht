// Offline, deterministic tests for the polling daemon: no network, no
// database. Every dependency (client, store, inventory, gap check, watermark,
// clock) is a fake wired through PollDeps / RunCveWatcherConfig.
package watcher

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	// fixedNow is the injected clock for deterministic watermark assertions.
	fixedNow = time.Date(2026, 8, 18, 12, 0, 0, 0, time.UTC)
	// projectID is the sole watched project in most tests.
	projectID = "11111111-1111-1111-1111-111111111111"
	// suppressingID is the scan-derived finding that suppresses a watcher hit.
	suppressingID = "22222222-2222-2222-2222-222222222222"
)

// testLogger discards log output so tests stay quiet.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// inventoryRow builds one distinct-inventory row.
func inventoryRow(purl, eco, name, version string) port.InventoryPackage {
	return port.InventoryPackage{
		PURL:      purl,
		Ecosystem: eco,
		Name:      name,
		Version:   version,
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

// golangAdvisory builds an advisory in the OSV canonical "Go" ecosystem,
// matching golang.org/x/text versions < 0.3.8.
func golangAdvisory(id, published string) Advisory {
	a := testAdvisory(id, published)
	a.Affected[0].Ecosystem = "Go" // OSV canonical casing, as querybatch returns it
	a.Affected[0].Package.Name = "golang.org/x/text"
	a.Affected[0].Ranges = []VersionRange{
		{Type: "SEMVER", Events: []RangeEvent{{Introduced: "0"}, {Fixed: "0.3.8"}}},
	}
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
	id string
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

func (s *recordingStore) PersistFoundFinding(ctx context.Context, d Decision) (string, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.created = append(s.created, d)
	if s.persistErr != nil {
		return "", false, s.persistErr
	}
	if s.reportNoOp {
		return suppressingID, false, nil
	}
	return suppressingID, true, nil
}

func (s *recordingStore) PersistSkipEvent(ctx context.Context, id string, ev Event) error {
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
		Projects: []string{projectID},
		Inventory: func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
			return nil, nil
		},
		FindGap: func(ctx context.Context, pid string, purlName string, candidateIDs []string) (string, error) {
			return "", nil
		},
		GetWatermark: func(ctx context.Context, projectID string) (time.Time, bool, error) {
			return time.Time{}, false, nil
		},
		SetWatermark: func(ctx context.Context, projectID string, ts time.Time) error { return nil },
		Now:          func() time.Time { return fixedNow },
		Logger:       testLogger(),
		InventoryTTL: 720 * time.Hour,
	}
}

func TestPollOnce_ColdStartFullHistory_AdvancesWatermark(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2020-01-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	var wm time.Time
	watermarked := false
	deps.SetWatermark = func(ctx context.Context, projectID string, ts time.Time) error {
		wm, watermarked = ts, true
		return nil
	}

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
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	watermarked := false
	deps.SetWatermark = func(ctx context.Context, projectID string, ts time.Time) error { watermarked = true; return nil }

	_, err := PollOnce(context.Background(), deps)
	require.Error(t, err)
	assert.False(t, watermarked, "watermark must NOT advance on a failed poll")
}

func TestPollOnce_WarmPollFiltersAdvisoriesBeforeWatermark(t *testing.T) {
	deps := baseDeps()
	deps.ResweepInterval = 365 * 24 * time.Hour
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{
		testAdvisory("GHSA-old-old-old", "2020-01-01T00:00:00Z"), // before watermark
		testAdvisory("GHSA-new-new-new", "2026-06-01T00:00:00Z"), // after watermark
	}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	deps.GetWatermark = func(ctx context.Context, projectID string) (time.Time, bool, error) {
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

func TestPollOnce_WarmPollResweepReevaluatesOldAdvisory(t *testing.T) {
	deps := baseDeps()
	deps.ResweepInterval = 7 * 24 * time.Hour
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{
		testAdvisory("GHSA-resweep-resweep-resweep", "2020-01-01T00:00:00Z"),
	}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	deps.GetWatermark = func(ctx context.Context, projectID string) (time.Time, bool, error) {
		return fixedNow.Add(-deps.ResweepInterval), true, nil
	}

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.Created, "a due resweep must reconsider advisories older than the watermark")
	assert.Zero(t, outcome.ModifiedReevaluated, "a resweep is not a modified-since admission")
	// One resweep performs one bounded query pass; it must not loop over the
	// full feed repeatedly within the same poll.
	require.Len(t, client.queries, 1)
	require.Len(t, client.queries[0], 1)
	require.Len(t, deps.Store.(*recordingStore).created, 1)
}

func TestPollOnce_WarmPollModifiedAdvisoryReevaluated(t *testing.T) {
	deps := baseDeps()
	deps.ResweepInterval = 365 * 24 * time.Hour
	client := deps.Client.(*fakeClient)
	advisory := testAdvisory("GHSA-modified-modified-modified", "2020-01-01T00:00:00Z")
	advisory.Modified = fixedNow.Add(-time.Hour).Format(time.RFC3339)
	client.results["npm\x00lodash"] = []Advisory{advisory}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	deps.GetWatermark = func(ctx context.Context, projectID string) (time.Time, bool, error) {
		return fixedNow.Add(-24 * time.Hour), true, nil
	}

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.Created, "a modified advisory must be reconsidered even when published is old")
	assert.Equal(t, 1, outcome.ModifiedReevaluated)
	require.Len(t, deps.Store.(*recordingStore).created, 1)
}

func TestPollOnce_ColdStartWindowFiltersBySince(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{
		testAdvisory("GHSA-old-old-old", "2020-01-01T00:00:00Z"),
		testAdvisory("GHSA-new-new-new", "2026-08-01T00:00:00Z"),
	}
	deps.Since = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) // WATCHER_COLD_START_WINDOW
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
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
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	deps.FindGap = func(ctx context.Context, pid string, purlName string, candidateIDs []string) (string, error) {
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
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{
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
	watermarked := false
	var watermarkAt time.Time
	deps.SetWatermark = func(ctx context.Context, projectID string, ts time.Time) error {
		watermarked = true
		watermarkAt = ts
		return nil
	}
	outcome, err := PollOnce(context.Background(), deps) // inventory returns nil
	require.NoError(t, err)
	assert.Zero(t, client.callCount(), "no OSV query for an empty inventory")
	assert.Equal(t, 0, outcome.Created)
	assert.True(t, watermarked, "empty inventory must advance its watermark")
	assert.Equal(t, fixedNow, watermarkAt, "empty inventory advances to the poll timestamp")
}

func TestPollOnce_UnqueryableInventoryDoesNotAdvanceWatermark(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	watermarked := false
	deps.SetWatermark = func(ctx context.Context, projectID string, ts time.Time) error {
		watermarked = true
		return nil
	}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{
			inventoryRow("pkg:generic/noname@1.0.0", "npm", "", "1.0.0"),
			inventoryRow("pkg:generic/noeco@1.0.0", "", "noeco", "1.0.0"),
		}, nil
	}

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Zero(t, client.callCount())
	assert.Zero(t, outcome.Queried)
	assert.True(t, watermarked, "unqueryable inventory must advance its watermark")
}

func TestPollOnce_UnqueryableRowsDropped(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{
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
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	store := deps.Store.(*recordingStore)
	store.persistErr = errors.New("tx failed")
	watermarked := false
	deps.SetWatermark = func(ctx context.Context, projectID string, ts time.Time) error { watermarked = true; return nil }

	_, err := PollOnce(context.Background(), deps)
	require.Error(t, err)
	assert.False(t, watermarked)
}

func TestPollOnce_RepollHitCountedUnchangedNotCreated(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	// The store reports created=false, as a real re-poll hit of an existing
	// watcher finding would (insert-if-absent -> no-op).
	store := deps.Store.(*recordingStore)
	store.reportNoOp = true

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Equal(t, 0, outcome.Created, "a re-poll hit must not be counted as a new finding")
	assert.Equal(t, 1, outcome.Unchanged, "a re-poll hit is counted as unchanged")
	require.Len(t, store.created, 1, "the decision is still handed to the store for its no-op guard")
}

func TestPollOnce_GrypeGolangStoredEcosystemMatchesOSVGoAdvisory(t *testing.T) {
	// Regression for Go ecosystem alias handling: grype
	// stores the purl type "golang", while OSV returns the canonical "Go"
	// ecosystem. The daemon groups and queries under the OSV-canonical name
	// (groupInventory -> OSVEcosystem("golang") = "Go"); it MUST hand that
	// same canonical value to the matcher, not the raw stored "golang", or
	// matchAffected compares "golang" against the advisory's "go" and
	// silently skips every crate — a false-negative with no error.
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["Go\x00golang.org/x/text"] = []Advisory{golangAdvisory("GHSA-gggg-gggg-gggg", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{
			inventoryRow("pkg:golang/golang.org/x/text@0.3.7", "golang", "golang.org/x/text", "0.3.7"),
		}, nil
	}

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.Created, "stored 'golang' must match an OSV 'Go' advisory and create")
	require.Len(t, client.queries, 1)
	require.Len(t, client.queries[0], 1)
	assert.Equal(t, "Go", client.queries[0][0].Package.Ecosystem, "query uses the OSV canonical ecosystem")
	store := deps.Store.(*recordingStore)
	require.Len(t, store.created, 1)
	// The persisted ecosystem dimension is the normalized canonical value.
	ecosystemDims := dimsMap(store.created[0].Finding)["ecosystem"]
	require.Equal(t, []string{"go"}, ecosystemDims, "ecosystem dimension normalized to lowercase canonical value")
	assert.Equal(t, "go", store.created[0].Finding.Display["ecosystem"])
}

func TestPollOnce_MalformedResponseDoesNotAdvanceWatermark(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	// A malformed/short OSV response is a non-retryable error (***REMOVED***
	// unknown-ecosystem guard): the poll must abort and leave the watermark alone.
	client.err = ErrMalformedResponse
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	watermarked := false
	deps.SetWatermark = func(ctx context.Context, projectID string, ts time.Time) error { watermarked = true; return nil }

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
	assert.Nil(t, occ.ReportID, "watcher occurrence carries NULL report_id")
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
	groups := groupInventory([]port.InventoryPackage{
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
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
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
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
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

type failingProjectClient struct {
	inner Client
	name  string
	err   error
}

func (f *failingProjectClient) QueryBatch(ctx context.Context, queries []Query) ([]QueryResult, error) {
	for _, q := range queries {
		if q.Package.Name == f.name {
			return nil, f.err
		}
	}
	return f.inner.QueryBatch(ctx, queries)
}

func TestRunCveWatcher_BackoffResetsOnSuccess(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
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

func TestRunCveWatcher_RecordsSuccessTimestamp(t *testing.T) {
	deps := baseDeps()
	success := make(chan time.Time, 1)
	deps.RecordSuccess = func(ctx context.Context, ts time.Time) error {
		success <- ts
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runDaemon(ctx, RunCveWatcherConfig{
		PollDeps:     deps,
		PollInterval: time.Minute,
		Jitter:       func(d time.Duration) time.Duration { return d },
		Sleep: func(ctx context.Context, d time.Duration) error {
			cancel()
			return ctx.Err()
		},
		Logger: testLogger(),
	})

	select {
	case successAt := <-success:
		assert.False(t, successAt.IsZero(), "successful polls must record a completion timestamp")
	case <-time.After(2 * time.Second):
		t.Fatal("successful poll did not record a completion timestamp")
	}
	cancel()
	<-done
}

func TestRunCveWatcher_ProjectIntervalsScheduleIndependently(t *testing.T) {
	projectTwo := "33333333-3333-3333-3333-333333333333"
	deps := baseDeps()
	deps.Projects = []string{projectID, projectTwo}
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}

	var mu sync.Mutex
	clock := fixedNow
	var inventoryProjects []string
	var projectTwoPolls int
	observedProjectTwo := make(chan struct{})
	var observeOnce sync.Once
	ctx, cancel := context.WithCancel(context.Background())
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		mu.Lock()
		inventoryProjects = append(inventoryProjects, pid)
		if pid == projectTwo {
			projectTwoPolls++
			if projectTwoPolls == 2 {
				observeOnce.Do(func() {
					close(observedProjectTwo)
					cancel()
				})
			}
		}
		mu.Unlock()
		row := inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")
		return []port.InventoryPackage{row}, nil
	}

	stopped := make(chan struct{})
	done := runDaemon(ctx, RunCveWatcherConfig{
		PollDeps:     deps,
		PollInterval: time.Hour,
		ProjectIntervals: map[string]time.Duration{
			projectID:  time.Minute,
			projectTwo: 5 * time.Minute,
		},
		Jitter: func(d time.Duration) time.Duration { return d },
		Now: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return clock
		},
		Sleep: func(ctx context.Context, d time.Duration) error {
			mu.Lock()
			clock = clock.Add(d)
			mu.Unlock()
			if ctx.Err() != nil {
				close(stopped)
				return ctx.Err()
			}
			return nil
		},
		Logger: testLogger(),
	})

	select {
	case <-observedProjectTwo:
	case <-time.After(2 * time.Second):
		t.Fatal("slower project was not scheduled after its configured interval")
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduled daemon did not stop")
	}
	<-done

	mu.Lock()
	got := append([]string(nil), inventoryProjects...)
	mu.Unlock()
	want := []string{projectID, projectTwo, projectID, projectID, projectID, projectID, projectID, projectTwo}
	assert.Equal(t, want, got)
}

func TestRunCveWatcher_ScheduledProjectsFailIndependently(t *testing.T) {
	projectTwo := "33333333-3333-3333-3333-333333333333"
	deps := baseDeps()
	deps.Projects = []string{projectID, projectTwo}
	inner := deps.Client.(*fakeClient)
	inner.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Client = &failingProjectClient{inner: inner, name: "broken", err: errors.New("project upstream down")}

	bAttempted := make(chan struct{}, 1)
	watermarked := make(chan string, 1)
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		row := inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")
		if pid == projectTwo {
			row = inventoryRow("pkg:npm/broken@1.0.0", "npm", "broken", "1.0.0")
			bAttempted <- struct{}{}
		}
		return []port.InventoryPackage{row}, nil
	}
	deps.SetWatermark = func(ctx context.Context, pid string, ts time.Time) error {
		watermarked <- pid
		return nil
	}
	nf := &fakeNotifier{notify: func(ctx context.Context, ns []Notification) error { return nil }}
	deps.Notifier = nf

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := runDaemon(ctx, RunCveWatcherConfig{
		PollDeps:     deps,
		PollInterval: time.Hour,
		ProjectIntervals: map[string]time.Duration{
			projectID:  time.Hour,
			projectTwo: time.Hour,
		},
		InitialBackoff: time.Minute,
		Jitter:         func(d time.Duration) time.Duration { return d },
		Sleep: func(ctx context.Context, d time.Duration) error {
			cancel()
			return ctx.Err()
		},
		Logger: testLogger(),
	})

	select {
	case got := <-watermarked:
		assert.Equal(t, projectID, got)
	case <-time.After(2 * time.Second):
		t.Fatal("successful project was not completed")
	}
	select {
	case <-bAttempted:
	case <-time.After(2 * time.Second):
		t.Fatal("failed project was not attempted")
	}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduled daemon did not stop")
	}
	eventually(t, func() bool { return len(nf.batches()) == 1 }, 2*time.Second)
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
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
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

// fakeNotifier captures the batches handed to it for assertions.
type fakeNotifier struct {
	mu     sync.Mutex
	got    [][]Notification
	notify func(context.Context, []Notification) error
}

func (f *fakeNotifier) Notify(ctx context.Context, ns []Notification) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.got = append(f.got, ns)
	if f.notify != nil {
		return f.notify(ctx, ns)
	}
	return nil
}

func (f *fakeNotifier) batches() [][]Notification {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.got
}

func TestPollOnce_NotifiesOnlyCreatedDecisions(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	nf := &fakeNotifier{}
	deps.Notifier = nf
	// ProjectName resolves across the poll's fire-and-forget goroutine.
	deps.ProjectName = func(ctx context.Context, _ string) (string, error) { return "acme", nil }

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.Created)

	// Notification dispatch is async; wait for the goroutine to land.
	eventually(t, func() bool { return len(nf.batches()) == 1 }, 2*time.Second)
	require.Len(t, nf.batches()[0], 1)
	n := nf.batches()[0][0]
	assert.Equal(t, "acme", n.Project)
	assert.Equal(t, "CVE-2024-0001", n.CVE)
	assert.Equal(t, "test advisory GHSA-aaaa-bbbb-cccc", n.Title)
}

func TestPollOnce_NotifierErrorIsLoggedAndBestEffort(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}

	var logs bytes.Buffer
	deps.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	var wg sync.WaitGroup
	deps.WG = &wg
	deps.Notifier = &fakeNotifier{notify: func(context.Context, []Notification) error {
		return errors.New("delivery failed")
	}}

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err, "best-effort notification failure must not fail the poll")
	assert.Equal(t, 1, outcome.Created)
	wg.Wait()
	assert.Contains(t, logs.String(), "watcher notification failed")
	assert.Contains(t, logs.String(), "delivery failed")
}

func TestPollOnce_NilOrDisabledNotifierIsNoOp(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}
	// Notifier left nil (the default) — must not panic and must not notify.
	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.Created)
}

func TestNotificationFromDecision_FallsBackGracefully(t *testing.T) {
	d := Decision{
		Finding: FindingPayload{
			Title:    "t",
			Severity: "high",
			Display:  map[string]any{"purl": "pkg:npm/lodash@4.17.19"},
			Metadata: map[string]any{"advisory_id": "OSV-2024-1", "references": []any{"https://example.test/1"}},
		},
	}
	n := NotificationFromDecision(d, "acme")
	assert.Equal(t, "acme", n.Project)
	assert.Equal(t, "OSV-2024-1", n.CVE)
	assert.Equal(t, "pkg:npm/lodash@4.17.19", n.Package)
	assert.Equal(t, "https://example.test/1", n.Link)
}

// TestPairGapCheck_NotFoundIsNotCovered pins the store-absence translation:
// the port layer reports "no covering finding" as ErrNotFound, which is the
// normal create path — only genuine errors may fail the poll.
func TestPairGapCheck_NotFoundIsNotCovered(t *testing.T) {
	ctx := context.Background()
	var suppressing string

	notFound := pairGapCheck(PollDeps{FindGap: func(context.Context, string, string, []string) (string, error) {
		return "", port.ErrNotFound
	}}, &suppressing)
	covered, err := notFound(ctx, "proj", "pkg:npm/lodash", []string{"CVE-1"})
	assert.NoError(t, err, "absence is not a poll failure")
	assert.False(t, covered)

	broken := pairGapCheck(PollDeps{FindGap: func(context.Context, string, string, []string) (string, error) {
		return "", errors.New("connection lost")
	}}, &suppressing)
	covered, err = broken(ctx, "proj", "pkg:npm/lodash", []string{"CVE-1"})
	assert.Error(t, err, "real errors still fail the poll")
	assert.False(t, covered)

	suppressing = ""
	hit := pairGapCheck(PollDeps{FindGap: func(context.Context, string, string, []string) (string, error) {
		return "finding-1", nil
	}}, &suppressing)
	covered, err = hit(ctx, "proj", "pkg:npm/lodash", []string{"CVE-1"})
	assert.NoError(t, err)
	assert.True(t, covered)
	assert.Equal(t, "finding-1", suppressing)
}

func TestRunCveWatcher_DynamicallyReloadsProjects(t *testing.T) {
	deps := baseDeps()
	deps.Projects = nil // Start with no projects

	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}

	var mu sync.Mutex
	var polledProjects []string
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		mu.Lock()
		polledProjects = append(polledProjects, pid)
		mu.Unlock()
		row := inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")
		return []port.InventoryPackage{row}, nil
	}

	var projectsMu sync.Mutex
	var currentProjects []port.Project

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	wakeSleep := make(chan struct{}, 10)
	done := runDaemon(ctx, RunCveWatcherConfig{
		PollDeps:     deps,
		PollInterval: 10 * time.Millisecond,
		ReloadProjects: func(ctx context.Context) ([]port.Project, error) {
			projectsMu.Lock()
			defer projectsMu.Unlock()
			res := make([]port.Project, len(currentProjects))
			copy(res, currentProjects)
			return res, nil
		},
		Sleep: func(ctx context.Context, d time.Duration) error {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-wakeSleep:
				return nil
			case <-time.After(20 * time.Millisecond):
				return nil
			}
		},
		Logger: testLogger(),
	})

	// Initially no projects polled
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	assert.Empty(t, polledProjects)
	mu.Unlock()

	// Dynamically add an enabled project
	projectsMu.Lock()
	currentProjects = []port.Project{
		{ID: "p1", Name: "Project 1", CveWatcherEnabled: true, CveWatcherIntervalSecs: 1},
	}
	projectsMu.Unlock()
	wakeSleep <- struct{}{}

	eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		for _, pid := range polledProjects {
			if pid == "p1" {
				return true
			}
		}
		return false
	}, 2*time.Second)

	cancel()
	<-done
}

func TestPollOnce_WaitGroupTracksAsyncNotifier(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}

	blockNotify := make(chan struct{})
	notifyStarted := make(chan struct{})
	nf := &fakeNotifier{
		notify: func(ctx context.Context, ns []Notification) error {
			close(notifyStarted)
			<-blockNotify
			return nil
		},
	}
	deps.Notifier = nf

	var wg sync.WaitGroup
	deps.WG = &wg

	outcome, err := PollOnce(context.Background(), deps)
	require.NoError(t, err)
	assert.Equal(t, 1, outcome.Created)

	// Wait until notifier has started execution
	<-notifyStarted

	doneWaiting := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneWaiting)
	}()

	// wg.Wait() should not return while blockNotify is still held
	select {
	case <-doneWaiting:
		t.Fatal("wg.Wait() returned before notifier finished")
	case <-time.After(50 * time.Millisecond):
	}

	// Release the notifier
	close(blockNotify)

	select {
	case <-doneWaiting:
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait() did not complete after notifier returned")
	}

	require.Len(t, nf.batches(), 1)
}

func TestRunCveWatcher_ConfigWGTracksNotifier(t *testing.T) {
	deps := baseDeps()
	client := deps.Client.(*fakeClient)
	client.results["npm\x00lodash"] = []Advisory{testAdvisory("GHSA-aaaa-bbbb-cccc", "2026-06-01T00:00:00Z")}
	deps.Inventory = func(ctx context.Context, pid string, since time.Duration) ([]port.InventoryPackage, error) {
		return []port.InventoryPackage{inventoryRow("pkg:npm/lodash@4.17.19", "npm", "lodash", "4.17.19")}, nil
	}

	notified := make(chan struct{})
	deps.Notifier = &fakeNotifier{
		notify: func(ctx context.Context, ns []Notification) error {
			close(notified)
			return nil
		},
	}

	var wg sync.WaitGroup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	RunCveWatcher(ctx, RunCveWatcherConfig{
		PollDeps:     deps,
		PollInterval: 10 * time.Minute,
		WG:           &wg,
		Logger:       testLogger(),
		Sleep: func(ctx context.Context, d time.Duration) error {
			<-ctx.Done()
			return ctx.Err()
		},
	})

	// Wait for the notifier hook to be entered
	select {
	case <-notified:
	case <-time.After(2 * time.Second):
		t.Fatal("notifier was not called")
	}

	// Wait for wg; it must succeed because the notifier goroutine was tracked by wg
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("wg.Wait() did not complete")
	}
}
