// Package intel fetches and caches external vulnerability intelligence
// (EPSS scores, CISA KEV membership) keyed by CVE identifier, and feeds the
// accepted signals into the risk model.
//
// Design points, per //   - Provider is the seam: each feed implements Fetch; the store merges
//
//	  records per CVE. Tests inject httptest servers; production uses the
//	  public EPSS API and the CISA KEV catalog.
//	- Records carry source, fetch time, and feed dates, so provenance is
//	  never separated from the value.
//	- Refresh policy is TTL-based: stale records are still served but
//	  flagged, and a failed refresh never erases the last known record.
//	- Only CVE identifiers are queryable; anything else is explicitly
//	  non-applicable (IsCVE). KEV absence is not a negative assertion:
//	  risk.HasKnownExploit is set only on positive membership.
//
// The cache is in-memory and holds at most DefaultMaxRecords CVEs; past that
// the least recently looked-up record is dropped. Intel is cheap to re-fetch
// and every record carries its own timestamp, so no migration or persistence
// adapter is needed; a restart or an eviction simply refetches on demand.
package intel

import (
	"context"
	"regexp"
	"sync"
	"time"

	"github.com/minh-tg/specht/internal/risk"
)

// Record is one CVE's merged intelligence with its provenance.
type Record struct {
	CVEID string   `json:"cve_id"`
	EPSS  *float64 `json:"epss,omitempty"`
	// EPSSPercentile is the score's rank among all CVEs in [0, 1]; zero means
	// the feed gave none.
	EPSSPercentile float64 `json:"epss_percentile,omitempty"`
	EPSSDate       string  `json:"epss_date,omitempty"`
	KEV            bool    `json:"kev"`
	KEVAdded       string  `json:"kev_added,omitempty"`
	// KEVDueDate is the date CISA requires federal agencies to remediate by.
	KEVDueDate string `json:"kev_due_date,omitempty"`
	// KEVRansomware is the catalog's knownRansomwareCampaignUse value, for
	// example "Known" or "Unknown". Empty when the catalog entry has none.
	KEVRansomware string    `json:"kev_ransomware,omitempty"`
	Sources       []string  `json:"sources"`
	FetchedAt     time.Time `json:"fetched_at"`
	Stale         bool      `json:"stale,omitempty"`
}

// Provider fetches intel for CVE identifiers from one feed.
type Provider interface {
	// Name identifies the feed in Record.Sources.
	Name() string
	// Fetch returns records for the requested CVEs. CVEs the feed knows
	// nothing about are simply absent from the map.
	Fetch(ctx context.Context, cveIDs []string) (map[string]Record, error)
}

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,7}$`)

// IsCVE reports whether id is a well-formed CVE identifier (the only shape
// feeds can match reliably). An id that merely starts with "CVE-" is not
// refreshed, so a made-up id never costs an outbound request.
func IsCVE(id string) bool {
	return cvePattern.MatchString(id)
}

// DefaultMaxRecords caps how many CVE records a Store keeps. Every distinct
// CVE read through a finding detail adds one, so without a cap a long-running
// server grows the map for its whole lifetime.
const DefaultMaxRecords = 10000

// Store caches merged records with a TTL refresh policy.
type Store struct {
	mu         sync.Mutex
	ttl        time.Duration
	now        func() time.Time
	providers  []Provider
	maxRecords int
	cached     map[string]Record
	// lastUsed is when each cached CVE was last looked up or stored; the
	// oldest goes first when the cache is full.
	lastUsed map[string]time.Time
}

// NewStore builds a store over the given providers. A nil now uses time.Now.
func NewStore(ttl time.Duration, now func() time.Time, providers ...Provider) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{
		ttl:        ttl,
		now:        now,
		providers:  providers,
		maxRecords: DefaultMaxRecords,
		cached:     map[string]Record{},
		lastUsed:   map[string]time.Time{},
	}
}

// Lookup returns the cached record and whether it is stale. Absent records
// report ok=false; call Refresh to fetch.
func (s *Store) Lookup(cveID string) (rec Record, stale, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rec, ok = s.cached[cveID]
	if !ok {
		return Record{}, false, false
	}
	s.lastUsed[cveID] = s.now()
	if s.now().Sub(rec.FetchedAt) > s.ttl {
		rec.Stale = true
	}
	return rec, rec.Stale, true
}

// Refresh fetches every requested CVE from all providers and merges the
// results. A provider failure keeps the previously cached records (still
// served, flagged stale on lookup) and returns the provider error.
func (s *Store) Refresh(ctx context.Context, cveIDs []string) error {
	want := make([]string, 0, len(cveIDs))
	for _, id := range cveIDs {
		if IsCVE(id) {
			want = append(want, id)
		}
	}
	if len(want) == 0 {
		return nil
	}
	merged, firstErr := s.fetchProviders(ctx, want)
	if len(merged) == 0 {
		return firstErr
	}
	s.mergeCached(merged)
	return firstErr
}

// fetchProviders queries every provider and merges their records per CVE;
// provider failures are collected into firstErr and do not abort the rest.
func (s *Store) fetchProviders(ctx context.Context, want []string) (map[string]Record, error) {
	merged := make(map[string]Record, len(want))
	var firstErr error
	for _, p := range s.providers {
		got, err := p.Fetch(ctx, want)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for id, rec := range got {
			m := merged[id]
			m.CVEID = id
			if rec.EPSS != nil {
				m.EPSS, m.EPSSPercentile, m.EPSSDate = rec.EPSS, rec.EPSSPercentile, rec.EPSSDate
			}
			if rec.KEV {
				m.KEV, m.KEVAdded = true, rec.KEVAdded
				m.KEVDueDate, m.KEVRansomware = rec.KEVDueDate, rec.KEVRansomware
			}
			m.Sources = append(m.Sources, p.Name())
			m.FetchedAt = s.now()
			merged[id] = m
		}
	}
	return merged, firstErr
}

// mergeCached folds fetched records into the cache under the write lock.
func (s *Store) mergeCached(merged map[string]Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, rec := range merged {
		s.lastUsed[id] = s.now()
		existing, exists := s.cached[id]
		if !exists {
			s.evictForNewLocked()
			s.cached[id] = rec
			continue
		}
		if rec.EPSS != nil {
			existing.EPSS = rec.EPSS
			existing.EPSSPercentile = rec.EPSSPercentile
			existing.EPSSDate = rec.EPSSDate
		}
		if rec.KEV {
			existing.KEV = true
			existing.KEVAdded = rec.KEVAdded
			existing.KEVDueDate = rec.KEVDueDate
			existing.KEVRansomware = rec.KEVRansomware
		}
		existing.Sources = unionStrings(existing.Sources, rec.Sources)
		existing.FetchedAt = rec.FetchedAt
		existing.Stale = false
		s.cached[id] = existing
	}
}

// evictForNewLocked makes room for one new record by dropping least recently
// used records until the cache is below its cap. The scan is linear, which
// only runs once the cache is full and costs far less than the feed fetch
// that produced the new record. Callers hold mu.
func (s *Store) evictForNewLocked() {
	if s.maxRecords <= 0 {
		return
	}
	for len(s.cached) >= s.maxRecords {
		var oldestID string
		var oldest time.Time
		first := true
		for id := range s.cached {
			used := s.lastUsed[id]
			if first || used.Before(oldest) || (used.Equal(oldest) && id < oldestID) {
				oldestID, oldest, first = id, used, false
			}
		}
		delete(s.cached, oldestID)
		delete(s.lastUsed, oldestID)
	}
}

// unionStrings appends the members of add that base does not already hold.
func unionStrings(base, add []string) []string {
	for _, s := range add {
		found := false
		for _, b := range base {
			if b == s {
				found = true
				break
			}
		}
		if !found {
			base = append(base, s)
		}
	}
	return base
}

// ApplyToSignals feeds a cached record into risk signals: positive KEV
// membership sets HasKnownExploit. It returns false when no record is
// cached or the record carries no exploit assertion.
func (s *Store) ApplyToSignals(cveID string, sig *risk.Signals) (Record, bool) {
	rec, _, ok := s.Lookup(cveID)
	if !ok || !rec.KEV {
		return rec, false
	}
	yes := true
	sig.HasKnownExploit = &yes
	return rec, true
}
