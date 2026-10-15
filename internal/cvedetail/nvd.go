package cvedetail

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

// DefaultNVDBaseURL is the NVD CVE API 2.0 endpoint.
const DefaultNVDBaseURL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

// NVD looks CVEs up in the NVD CVE API 2.0. The API key is optional; without
// one NVD allows 5 requests in 30 seconds, with one 50.
type NVD struct {
	BaseURL string
	APIKey  string
	Client  *http.Client
}

// Name implements Provider.
func (p *NVD) Name() string { return ProviderNVD }

// Lookup implements Provider. The key travels in the apiKey header. NVD
// answers 403 when a client exceeds its rate, so 403 counts as rate limited.
func (p *NVD) Lookup(ctx context.Context, cveID string) (Record, error) {
	base := p.BaseURL
	if base == "" {
		base = DefaultNVDBaseURL
	}
	var headers map[string]string
	if p.APIKey != "" {
		headers = map[string]string{"apiKey": p.APIKey}
	}
	var body nvdResponse
	err := getJSON(ctx, p.Client, base+"?cveId="+url.QueryEscape(cveID), headers, []int{http.StatusForbidden}, &body)
	if err != nil {
		return Record{}, err
	}
	for _, v := range body.Vulnerabilities {
		if v.CVE.ID == cveID {
			return v.CVE.record(), nil
		}
	}
	return Record{}, ErrNotFound
}

// nvdResponse is the subset of the NVD CVE API 2.0 response the provider reads.
type nvdResponse struct {
	Vulnerabilities []struct {
		CVE nvdCVE `json:"cve"`
	} `json:"vulnerabilities"`
}

// nvdCVE is one CVE object in the NVD 2.0 schema. VulnCheck's nist-nvd2 index
// serves the same shape.
type nvdCVE struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	Weaknesses   []struct {
		Description []struct {
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Metrics struct {
		V40 []nvdMetric `json:"cvssMetricV40"`
		V31 []nvdMetric `json:"cvssMetricV31"`
		V30 []nvdMetric `json:"cvssMetricV30"`
		V2  []nvdMetric `json:"cvssMetricV2"`
	} `json:"metrics"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
}

type nvdMetric struct {
	Source   string `json:"source"`
	Type     string `json:"type"`
	CVSSData struct {
		Version      string  `json:"version"`
		VectorString string  `json:"vectorString"`
		BaseScore    float64 `json:"baseScore"`
	} `json:"cvssData"`
}

// record converts the NVD object, newest CVSS version first and primary
// scores before secondary ones within a version.
func (c nvdCVE) record() Record {
	rec := Record{
		CVEID:     c.ID,
		Published: ParseTime(c.Published),
		Modified:  ParseTime(c.LastModified),
	}
	for _, group := range [][]nvdMetric{c.Metrics.V40, c.Metrics.V31, c.Metrics.V30, c.Metrics.V2} {
		for _, primary := range []bool{true, false} {
			for _, m := range group {
				if strings.EqualFold(m.Type, "Primary") != primary {
					continue
				}
				rec.CVSS = append(rec.CVSS, CVSSRecord{
					Version: m.CVSSData.Version,
					Vector:  m.CVSSData.VectorString,
					Score:   m.CVSSData.BaseScore,
					Source:  m.Source,
					Type:    m.Type,
				})
			}
		}
	}
	for _, w := range c.Weaknesses {
		for _, d := range w.Description {
			rec.CWEs = append(rec.CWEs, d.Value)
		}
	}
	for _, r := range c.References {
		rec.References = append(rec.References, r.URL)
	}
	return normalize(rec)
}
