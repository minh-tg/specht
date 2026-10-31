// Package intel KEV provider: membership in the CISA Known Exploited
// Vulnerabilities catalog (bulk JSON, matched locally by CVE identifier).
package intel

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/minh-tg/specht/internal/netutil"
)

// maxKEVResponseBytes bounds the catalog download. The feed is about 1.5 MiB
// today; the cap leaves room for years of growth.
const maxKEVResponseBytes = 32 << 20

// DefaultKEVCatalogTTL is how long a downloaded catalog is reused when
// KEVProvider.TTL is unset.
const DefaultKEVCatalogTTL = time.Hour

// KEVProvider fetches the CISA KEV catalog in bulk and keeps the parsed
// catalog for TTL, so a burst of single-CVE refreshes downloads it once.
// CatalogURL is injectable for tests; production is the CISA JSON feed.
type KEVProvider struct {
	CatalogURL string
	Client     *http.Client
	// TTL bounds how long a downloaded catalog is reused; zero means
	// DefaultKEVCatalogTTL.
	TTL time.Duration
	// Now overrides the clock in tests; nil means time.Now.
	Now func() time.Time

	// mu is held across a download, so concurrent callers share one fetch.
	mu       sync.Mutex
	entries  map[string]kevEntry
	loadedAt time.Time
}

// Name implements Provider.
func (p *KEVProvider) Name() string { return "kev" }

// kevEntry is what the catalog states about one listed CVE.
type kevEntry struct {
	DateAdded  string
	DueDate    string
	Ransomware string
}

type kevCatalog struct {
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		DateAdded                  string `json:"dateAdded"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
	} `json:"vulnerabilities"`
}

// Fetch implements Provider. The catalog is bulk-only, so it is downloaded
// when the held copy is older than the TTL and the requested subset that is
// KEV-listed is matched locally. A failed download returns the error and
// keeps the previous copy, which a later call past the TTL retries.
func (p *KEVProvider) Fetch(ctx context.Context, cveIDs []string) (map[string]Record, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.entries == nil || p.clock().Sub(p.loadedAt) >= p.ttl() {
		entries, err := p.download(ctx)
		if err != nil {
			return nil, err
		}
		p.entries, p.loadedAt = entries, p.clock()
	}
	out := make(map[string]Record)
	for _, id := range cveIDs {
		if e, ok := p.entries[id]; ok {
			out[id] = Record{CVEID: id, KEV: true, KEVAdded: e.DateAdded, KEVDueDate: e.DueDate, KEVRansomware: e.Ransomware}
		}
	}
	return out, nil
}

func (p *KEVProvider) ttl() time.Duration {
	if p.TTL > 0 {
		return p.TTL
	}
	return DefaultKEVCatalogTTL
}

func (p *KEVProvider) clock() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// download fetches the catalog and returns what it states per CVE id.
func (p *KEVProvider) download(ctx context.Context) (map[string]kevEntry, error) {
	catalogURL := p.CatalogURL
	if catalogURL == "" {
		catalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, catalogURL, nil)
	if err != nil {
		return nil, err
	}
	client := p.Client
	if client == nil {
		// The safe client refuses redirects and non-public addresses (a
		// loopback CatalogURL is the one exception). It is built per
		// download, so release its idle connections when the call ends.
		client = netutil.SafeHTTPClientForURL(catalogURL, 60*time.Second)
		defer client.CloseIdleConnections()
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("kev fetch: %w", err)
	}
	// Close errors cannot change the fetch result and are best-effort cleanup.
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kev fetch: status %d", resp.StatusCode)
	}
	var catalog kevCatalog
	if err := netutil.DecodeJSONLimited(resp.Body, maxKEVResponseBytes, &catalog); err != nil {
		return nil, fmt.Errorf("kev decode: %w", err)
	}
	entries := make(map[string]kevEntry, len(catalog.Vulnerabilities))
	for _, v := range catalog.Vulnerabilities {
		entries[v.CVEID] = kevEntry{DateAdded: v.DateAdded, DueDate: v.DueDate, Ransomware: v.KnownRansomwareCampaignUse}
	}
	return entries, nil
}
