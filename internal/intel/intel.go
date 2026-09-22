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
// The cache is in-memory. Intel is cheap to re-fetch and every record
// carries its own timestamp, so no migration or persistence adapter is
// needed; a restart simply refetches on demand.
package intel

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/minh-tg/specht/internal/risk"
)

// Record is one CVE's merged intelligence with its provenance.
type Record struct {
	CVEID     string    `json:"cve_id"`
	EPSS      *float64  `json:"epss,omitempty"`
	EPSSDate  string    `json:"epss_date,omitempty"`
	KEV       bool      `json:"kev"`
	KEVAdded  string    `json:"kev_added,omitempty"`
	Sources   []string  `json:"sources"`
	FetchedAt time.Time `json:"fetched_at"`
	Stale     bool      `json:"stale,omitempty"`
}

// Provider fetches intel for CVE identifiers from one feed.
type Provider interface {
	// Name identifies the feed in Record.Sources.
	Name() string
	// Fetch returns records for the requested CVEs. CVEs the feed knows
	// nothing about are simply absent from the map.
	Fetch(ctx context.Context, cveIDs []string) (map[string]Record, error)
}

// IsCVE reports whether id looks like a CVE identifier (the only shape
// feeds can match reliably).
func IsCVE(id string) bool {
	return strings.HasPrefix(id, "CVE-")
}

// Store caches merged records with a TTL refresh policy.
type Store struct {
	mu        sync.Mutex
	ttl       time.Duration
	now       func() time.Time
	providers []Provider
	cached    map[string]Record
}

// NewStore builds a store over the given providers. A nil now uses time.Now.
func NewStore(ttl time.Duration, now func() time.Time, providers ...Provider) *Store {
	if now == nil {
		now = time.Now
	}
	return &Store{ttl: ttl, now: now, providers: providers, cached: map[string]Record{}}
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
				m.EPSS, m.EPSSDate = rec.EPSS, rec.EPSSDate
			}
			if rec.KEV {
				m.KEV, m.KEVAdded = true, rec.KEVAdded
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
		existing, exists := s.cached[id]
		if !exists {
			s.cached[id] = rec
			continue
		}
		if rec.EPSS != nil {
			existing.EPSS = rec.EPSS
			existing.EPSSDate = rec.EPSSDate
		}
		if rec.KEV {
			existing.KEV = true
			existing.KEVAdded = rec.KEVAdded
		}
		existing.Sources = unionStrings(existing.Sources, rec.Sources)
		existing.FetchedAt = rec.FetchedAt
		existing.Stale = false
		s.cached[id] = existing
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
