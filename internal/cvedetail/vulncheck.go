package cvedetail

import (
	"context"
	"net/http"
	"net/url"
)

// DefaultVulnCheckBaseURL is VulnCheck's NVD 2.0 index.
const DefaultVulnCheckBaseURL = "https://api.vulncheck.com/v3/index/nist-nvd2"

// VulnCheck looks CVEs up in VulnCheck's nist-nvd2 index, which serves NVD 2.0
// CVE objects. It needs an API key, sent as a bearer token.
type VulnCheck struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

// Name implements Provider.
func (p *VulnCheck) Name() string { return ProviderVulnCheck }

// Lookup implements Provider.
func (p *VulnCheck) Lookup(ctx context.Context, cveID string) (Record, error) {
	base := p.BaseURL
	if base == "" {
		base = DefaultVulnCheckBaseURL
	}
	headers := map[string]string{"Authorization": "Bearer " + p.APIKey}
	var body struct {
		Data []nvdCVE `json:"data"`
	}
	if err := getJSON(ctx, p.Client, base+"?cve="+url.QueryEscape(cveID), headers, nil, &body); err != nil {
		return Record{}, err
	}
	for _, c := range body.Data {
		if c.ID == cveID {
			return c.record(), nil
		}
	}
	return Record{}, ErrNotFound
}
