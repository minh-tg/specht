package sbom

import (
	"strconv"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
)

// cdxComponent is a CycloneDX component. Components can nest, so a package
// inside an assembly is still reachable by its bom-ref.
type cdxComponent struct {
	BOMRef     string         `json:"bom-ref"`
	Type       string         `json:"type"`
	Name       string         `json:"name"`
	Version    string         `json:"version"`
	PURL       string         `json:"purl"`
	Components []cdxComponent `json:"components"`
}

// flattenComponents lists every component, nested ones included, depth first.
func flattenComponents(components []cdxComponent) []cdxComponent {
	var out []cdxComponent
	for _, c := range components {
		out = append(out, c)
		out = append(out, flattenComponents(c.Components)...)
	}
	return out
}

type cdxVulnerability struct {
	ID     string `json:"id"`
	Source struct {
		Name string `json:"name"`
	} `json:"source"`
	References []struct {
		ID string `json:"id"`
	} `json:"references"`
	Ratings        []cdxRating `json:"ratings"`
	CWEs           []int       `json:"cwes"`
	Description    string      `json:"description"`
	Detail         string      `json:"detail"`
	Recommendation string      `json:"recommendation"`
	Advisories     []struct {
		URL string `json:"url"`
	} `json:"advisories"`
	Analysis *struct {
		State         string   `json:"state"`
		Justification string   `json:"justification"`
		Response      []string `json:"response"`
		Detail        string   `json:"detail"`
	} `json:"analysis"`
	Affects []struct {
		Ref string `json:"ref"`
	} `json:"affects"`
}

type cdxRating struct {
	Score    float64 `json:"score"`
	Severity string  `json:"severity"`
	Method   string  `json:"method"`
	Vector   string  `json:"vector"`
}

// maxAdvisories bounds how many advisory links ride on one finding.
const maxAdvisories = 10

// vulnerabilityFindings turns a CycloneDX vulnerabilities section into SCA
// findings, one for each vulnerability and affected component. The identity is
// the vulnerability id and the package URL, the same as every other SCA
// scanner, so the same flaw reported by Grype or Trivy is the same finding.
// It returns how many affected references named no known component.
func vulnerabilityFindings(vulns []cdxVulnerability, components []cdxComponent) (findings []domain.NormalizedFinding, unresolved int) {
	byRef := map[string]cdxComponent{}
	for _, c := range components {
		if c.BOMRef != "" {
			byRef[c.BOMRef] = c
		}
	}
	for _, v := range vulns {
		if v.ID == "" {
			continue
		}
		for _, a := range v.Affects {
			c, ok := byRef[a.Ref]
			if !ok && strings.HasPrefix(a.Ref, "pkg:") {
				_, name, version := domain.SplitPURL(a.Ref)
				c, ok = cdxComponent{Name: name, Version: version, PURL: a.Ref}, true
			}
			if !ok {
				unresolved++
				continue
			}
			findings = append(findings, parseutil.HardenFinding(vulnerabilityFinding(v, c)))
		}
	}
	return findings, unresolved
}

func vulnerabilityFinding(v cdxVulnerability, c cdxComponent) domain.NormalizedFinding {
	purl := c.PURL
	if purl == "" {
		// Without a package URL two components would share an identity. A
		// generic one built from name and version keeps them apart.
		purl = "pkg:generic/" + c.Name + "@" + c.Version
	}
	severity, cvss := ratingsOf(v.Ratings)

	description := v.Description
	if description == "" {
		description = v.Detail
	}
	var fix *domain.FixInfo
	if v.Recommendation != "" {
		fix = &domain.FixInfo{Summary: v.Recommendation}
	}
	var score float64
	if cvss != nil {
		score = cvss.Score
	}
	dims := []domain.Dimension{
		{Key: "vulnerability_id", Value: v.ID},
		{Key: "package_name", Value: c.Name},
		{Key: "installed_version", Value: c.Version},
		{Key: "purl", Value: purl},
	}
	if fix != nil {
		dims = append(dims, domain.Dimension{Key: "fixed_version", Value: fix.Summary})
	}

	ext := map[string]any{
		"package": map[string]any{"name": c.Name, "version": c.Version, "type": c.Type},
		"purl":    purl,
	}
	if v.Source.Name != "" {
		ext["source"] = v.Source.Name
	}
	if len(v.CWEs) > 0 {
		ext["cwes"] = v.CWEs
	}
	if links := advisoryLinks(v); len(links) > 0 {
		ext["advisories"] = links
	}
	if v.Analysis != nil {
		// The producer's own verdict is kept so a later import can use it. It does not
		// change the finding here: a file does not get to close a finding on its own.
		ext["cyclonedx_analysis"] = map[string]any{
			"state":         v.Analysis.State,
			"justification": v.Analysis.Justification,
			"response":      v.Analysis.Response,
			"detail":        v.Analysis.Detail,
		}
	}

	return domain.NormalizedFinding{
		Fingerprint: string(domain.SCAFingerprint(v.ID, purl)),
		FindingKind: "sca",
		Title:       v.ID + " in " + c.Name,
		Description: description,
		Severity:    severity,
		Score:       score,
		Location:    domain.SCALocation(c.Name, c.Version, ""),
		Resource:    c.Name + "@" + c.Version,
		Aliases:     aliasesOf(v),
		CVSS:        cvss,
		Fix:         fix,
		Dimensions:  dims,
		Extensions:  ext,
	}
}

// ratingsOf reads a vulnerability's ratings. The severity is the highest one
// any rating states; a rating with none, such as an EPSS score, does not lower
// it. The CVSS is the highest scoring rating that carries a vector.
func ratingsOf(ratings []cdxRating) (domain.Severity, *domain.CVSSInfo) {
	severity := domain.SeverityUnknown
	var best *cdxRating
	for i := range ratings {
		r := &ratings[i]
		if s := severityOf(r.Severity); s > severity {
			severity = s
		}
		if cvssVersion(r.Vector) != "" && (best == nil || r.Score > best.Score) {
			best = r
		}
	}
	if best == nil {
		return severity, nil
	}
	return severity, &domain.CVSSInfo{Version: cvssVersion(best.Vector), Vector: best.Vector, Score: best.Score}
}

func severityOf(s string) domain.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return domain.SeverityCritical
	case "high":
		return domain.SeverityHigh
	case "medium":
		return domain.SeverityMedium
	case "low":
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}

// cvssVersion names the CVSS version a vector uses: CVSS:3.1/... is 3.1, and a
// bare AV:N/... vector is version 2. Anything else is not a CVSS vector.
func cvssVersion(vector string) string {
	switch {
	case strings.HasPrefix(vector, "CVSS:"):
		if i := strings.IndexByte(vector, '/'); i > len("CVSS:") {
			return vector[len("CVSS:"):i]
		}
	case strings.HasPrefix(vector, "AV:"):
		return "2.0"
	}
	return ""
}

func aliasesOf(v cdxVulnerability) []string {
	var out []string
	seen := map[string]bool{v.ID: true}
	for _, r := range v.References {
		if r.ID != "" && !seen[r.ID] {
			seen[r.ID] = true
			out = append(out, r.ID)
		}
	}
	return out
}

func advisoryLinks(v cdxVulnerability) []string {
	var out []string
	for _, a := range v.Advisories {
		if a.URL != "" && len(out) < maxAdvisories {
			out = append(out, a.URL)
		}
	}
	return out
}

func itoa(n int) string { return strconv.Itoa(n) }
