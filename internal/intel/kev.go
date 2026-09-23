// Package intel KEV provider: membership in the CISA Known Exploited
// Vulnerabilities catalog (bulk JSON, matched locally by CVE identifier).
package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// KEVProvider fetches the CISA KEV catalog in bulk. CatalogURL is injectable
// for tests; production is the CISA JSON feed.
type KEVProvider struct {
	CatalogURL string
	Client     *http.Client
}

// Name implements Provider.
func (p *KEVProvider) Name() string { return "kev" }

type kevCatalog struct {
	Vulnerabilities []struct {
		CVEID     string `json:"cveID"`
		DateAdded string `json:"dateAdded"`
	} `json:"vulnerabilities"`
}

// Fetch implements Provider. The catalog is bulk-only, so every call
// downloads it and returns the requested subset that is KEV-listed.
func (p *KEVProvider) Fetch(ctx context.Context, cveIDs []string) (map[string]Record, error) {
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
		client = &http.Client{Timeout: 60 * time.Second}
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
	if err := json.NewDecoder(resp.Body).Decode(&catalog); err != nil {
		return nil, fmt.Errorf("kev decode: %w", err)
	}
	want := make(map[string]struct{}, len(cveIDs))
	for _, id := range cveIDs {
		want[id] = struct{}{}
	}
	out := make(map[string]Record)
	for _, v := range catalog.Vulnerabilities {
		if _, ok := want[v.CVEID]; !ok {
			continue
		}
		out[v.CVEID] = Record{CVEID: v.CVEID, KEV: true, KEVAdded: v.DateAdded}
	}
	return out, nil
}
