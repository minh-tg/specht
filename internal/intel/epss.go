// Package intel EPSS provider: batch lookup of exploit-prediction scores
// from the public FIRST EPSS API (https://api.first.org/data/v1/epss).
package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// EPSSProvider fetches EPSS scores in batches. BaseURL is injectable for
// tests; production is https://api.first.org/data/v1/epss.
type EPSSProvider struct {
	BaseURL string
	Client  *http.Client
}

// Name implements Provider.
func (p *EPSSProvider) Name() string { return "epss" }

type epssResponse struct {
	Status string `json:"status"`
	Data   []struct {
		CVE        string `json:"cve"`
		EPSS       string `json:"epss"`
		Percentile string `json:"percentile"`
		Date       string `json:"date"`
	} `json:"data"`
}

// Fetch implements Provider, batching in chunks of 100 (the API page size).
func (p *EPSSProvider) Fetch(ctx context.Context, cveIDs []string) (map[string]Record, error) {
	out := make(map[string]Record, len(cveIDs))
	for i := 0; i < len(cveIDs); i += 100 {
		end := min(i+100, len(cveIDs))
		if err := p.fetchBatch(ctx, cveIDs[i:end], out); err != nil {
			return out, err
		}
	}
	return out, nil
}

func (p *EPSSProvider) fetchBatch(ctx context.Context, cveIDs []string, out map[string]Record) error {
	base := p.BaseURL
	if base == "" {
		base = "https://api.first.org/data/v1/epss"
	}
	u := base + "?cve=" + url.QueryEscape(strings.Join(cveIDs, ","))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("epss fetch: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("epss fetch: status %d", resp.StatusCode)
	}
	var body epssResponse
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return fmt.Errorf("epss decode: %w", err)
	}
	for _, d := range body.Data {
		if !IsCVE(d.CVE) {
			continue
		}
		var score float64
		if _, err := fmt.Sscanf(d.EPSS, "%f", &score); err != nil {
			continue
		}
		out[d.CVE] = Record{CVEID: d.CVE, EPSS: &score, EPSSDate: d.Date}
	}
	return nil
}
