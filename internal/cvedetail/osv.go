package cvedetail

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// DefaultOSVBaseURL is the OSV vulnerability endpoint; the CVE identifier is
// appended as the last path segment.
const DefaultOSVBaseURL = "https://api.osv.dev/v1/vulns"

// OSV looks CVEs up in the OSV API, which mirrors the CVE list. It needs no key.
type OSV struct {
	BaseURL string
	Client  *http.Client
}

// Name implements Provider.
func (p *OSV) Name() string { return ProviderOSV }

// Lookup implements Provider.
func (p *OSV) Lookup(ctx context.Context, cveID string) (Record, error) {
	base := p.BaseURL
	if base == "" {
		base = DefaultOSVBaseURL
	}
	var body struct {
		ID        string `json:"id"`
		Published string `json:"published"`
		Modified  string `json:"modified"`
		Severity  []struct {
			Type  string `json:"type"`
			Score string `json:"score"`
		} `json:"severity"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
		DatabaseSpecific struct {
			CWEIDs []string `json:"cwe_ids"`
		} `json:"database_specific"`
	}
	if err := getJSON(ctx, p.Client, strings.TrimRight(base, "/")+"/"+url.PathEscape(cveID), nil, nil, &body); err != nil {
		return Record{}, err
	}
	if body.ID != cveID {
		return Record{}, ErrNotFound
	}
	rec := Record{
		CVEID:     cveID,
		Published: ParseTime(body.Published),
		Modified:  ParseTime(body.Modified),
		CWEs:      body.DatabaseSpecific.CWEIDs,
	}
	for _, s := range body.Severity {
		vector := NormalizeVector(s.Score)
		version := VectorVersion(vector)
		if version == "" {
			continue
		}
		rec.CVSS = append(rec.CVSS, CVSSRecord{Version: version, Vector: vector, Source: "osv"})
	}
	for _, r := range body.References {
		rec.References = append(rec.References, r.URL)
	}
	return normalize(rec), nil
}
