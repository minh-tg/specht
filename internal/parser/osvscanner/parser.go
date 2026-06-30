package osvscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/vulnserve/vulnserve/internal/scanner"
)

type osvReport struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource   `json:"source"`
	Packages []osvPkgResult `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvPkgResult struct {
	Package         osvPkg                `json:"package"`
	Vulnerabilities []osvVuln             `json:"vulnerabilities"`
	Groups          []osvGroup            `json:"groups"`
}

type osvPkg struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
}

type osvVuln struct {
	ID              string            `json:"id"`
	Aliases         []string          `json:"aliases"`
	Summary         string            `json:"summary"`
	Details         string            `json:"details"`
	Published       string            `json:"published"`
	Modified        string            `json:"modified"`
	Severity        []osvSeverity     `json:"severity"`
	DatabaseSpecific *osvDBSpecific   `json:"database_specific"`
	Affected        *osvAffected      `json:"affected"`
	References      []osvReference    `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvDBSpecific struct {
	Severity string `json:"severity"`
}

type osvAffected struct {
	Package  osvPkg         `json:"package"`
	Ranges   []osvRange     `json:"ranges"`
	Versions []string       `json:"versions"`
}

type osvRange struct {
	Type   string       `json:"type"`
	Events []osvRangeEvent `json:"events"`
}

type osvRangeEvent struct {
	Introduced string `json:"introduced"`
	Fixed      string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type osvReference struct {
	URL string `json:"url"`
}

type osvGroup struct {
	IDs                  []string                    `json:"ids"`
	ExperimentalAnalysis map[string]osvCallAnalysis  `json:"experimentalAnalysis"`
}

type osvCallAnalysis struct {
	Called *bool `json:"called"`
}

type Parser struct{}

func NewParser() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "osv-scanner" }

func (p *Parser) ScanTypes() []scanner.ScanType {
	return []scanner.ScanType{scanner.ScanTypeLockfile, scanner.ScanTypeSBOM, scanner.ScanTypeRepository}
}

func (p *Parser) Detect(data []byte) bool {
	var probe osvReport
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return len(probe.Results) > 0
}

func (p *Parser) Parse(ctx context.Context, r io.Reader) (*scanner.NormalizedReport, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("osv-scanner: read input: %w", err)
	}

	var report osvReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("osv-scanner: parse json: %w", err)
	}

	return convert(report), nil
}

func convert(report osvReport) *scanner.NormalizedReport {
	nr := &scanner.NormalizedReport{
		ScannerName: "osv-scanner",
		Findings:    nil,
		ScanScope:   make(map[string]any),
	}

	for _, result := range report.Results {
		nr.Target = &scanner.TargetInfo{
			Kind:       result.Source.Type,
			Identifier: result.Source.Path,
		}

		for _, pkg := range result.Packages {
			groupAnalysis := make(map[string]osvCallAnalysis, len(pkg.Groups))
			for _, g := range pkg.Groups {
				for id, analysis := range g.ExperimentalAnalysis {
					groupAnalysis[id] = analysis
				}
			}

			for _, v := range pkg.Vulnerabilities {
				severity := extractSeverity(v)
				score := extractScore(v)

				purl := v.Affected.Package.PURL
				if purl == "" {
					purl = "pkg:" + strings.ToLower(v.Affected.Package.Ecosystem) + "/" + v.Affected.Package.Name
				}
				pkgPURL := purl

				fingerprint := string(scanner.SCAFingerprint(v.ID, pkgPURL))

				var fixedVersion string
				if v.Affected != nil {
					for _, rng := range v.Affected.Ranges {
						for _, e := range rng.Events {
							if e.Fixed != "" {
								fixedVersion = e.Fixed
							}
						}
					}
				}

				dims := []scanner.Dimension{
					{Key: "vulnerability_id", Value: v.ID},
					{Key: "package_name", Value: pkg.Package.Name},
					{Key: "ecosystem", Value: pkg.Package.Ecosystem},
					{Key: "installed_version", Value: pkg.Package.Version},
					{Key: "purl", Value: pkgPURL},
				}
				if fixedVersion != "" {
					dims = append(dims, scanner.Dimension{Key: "fixed_version", Value: fixedVersion})
				}

				aliases := v.Aliases
				cveID := ""
				for _, alias := range aliases {
					if strings.HasPrefix(alias, "CVE-") {
						cveID = alias
						break
					}
				}

				display := map[string]any{
					"source_path": result.Source.Path,
					"ecosystem":   pkg.Package.Ecosystem,
				}
				if analysis, ok := groupAnalysis[v.ID]; ok && analysis.Called != nil {
					display["reachable"] = *analysis.Called
				}
				if cveID != "" {
					display["cve_id"] = cveID
				}

				meta := map[string]any{
					"osv_id":     v.ID,
					"ecosystem":  pkg.Package.Ecosystem,
					"aliases":    aliases,
					"published":  v.Published,
					"modified":   v.Modified,
				}

				if analysis, ok := groupAnalysis[v.ID]; ok && analysis.Called != nil {
					meta["call_analysis"] = *analysis.Called
				}

				title := v.Summary
				desc := v.Details

				nr.Findings = append(nr.Findings, scanner.NormalizedFinding{
					Fingerprint: fingerprint,
					FindingKind: "sca_vulnerability",
					Title:       title,
					Description: desc,
					Severity:    severity,
					Score:       score,
					Location:    result.Source.Path + ":" + pkg.Package.Name,
					Dimensions:  dims,
					Display:     display,
					Metadata:    meta,
				})
			}
		}
	}

	return nr
}

func extractSeverity(v osvVuln) scanner.Severity {
	if v.DatabaseSpecific != nil && v.DatabaseSpecific.Severity != "" {
		return normalizeOSVSeverity(v.DatabaseSpecific.Severity)
	}
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
			score, _, ok := parseCVSSScore(s.Score)
			if ok {
				return severityFromScore(score)
			}
		}
	}
	return scanner.SeverityUnknown
}

func extractScore(v osvVuln) float64 {
	for _, s := range v.Severity {
		if s.Type == "CVSS_V3" {
			score, _, ok := parseCVSSScore(s.Score)
			if ok {
				return score
			}
		}
	}
	for _, s := range v.Severity {
		if s.Type == "CVSS_V2" {
			score, _, ok := parseCVSSScore(s.Score)
			if ok {
				return score
			}
		}
	}
	return 0
}

func parseCVSSScore(s string) (float64, string, bool) {
	if s == "" {
		return 0, "", false
	}
	if strings.HasPrefix(s, "CVSS:") {
		score := cvss31BaseScore(s)
		if score > 0 {
			return score, s, true
		}
		return 0, s, false
	}
	var score float64
	if _, err := fmt.Sscanf(s, "%f", &score); err == nil {
		return score, s, true
	}
	return 0, s, false
}

func cvss31BaseScore(vector string) float64 {
	metrics := make(map[string]string)
	parts := strings.Split(vector, "/")
	for _, p := range parts {
		if idx := strings.Index(p, ":"); idx >= 0 {
			key := strings.TrimSpace(p[idx+1:])
			if idx2 := strings.Index(key, ":"); idx2 >= 0 {
				key = key[:idx2]
			}
			if key != "" {
				lastKey := p[:idx]
				if _, ok := metrics[lastKey]; !ok {
					metrics[lastKey] = key
				}
			}
		}
	}

	av := metricVal(metrics, "AV", map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2})
	ac := metricVal(metrics, "AC", map[string]float64{"L": 0.77, "H": 0.44})
	scope := metrics["S"]

	prUnchanged := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prChanged := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	pr := metricVal(metrics, "PR", prUnchanged)
	if scope == "C" {
		pr = metricVal(metrics, "PR", prChanged)
	}

	ui := metricVal(metrics, "UI", map[string]float64{"N": 0.85, "R": 0.62})

	c := metricVal(metrics, "C", impactVals)
	i := metricVal(metrics, "I", impactVals)
	a := metricVal(metrics, "A", impactVals)

	iss := 1.0 - (1.0-c)*(1.0-i)*(1.0-a)
	var impact float64
	if scope == "C" {
		impact = 7.52 * (iss - 0.029) - 3.25 * pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}

	exploitability := 8.22 * av * ac * pr * ui

	if impact <= 0 {
		return 0
	}

	var base float64
	if scope == "C" {
		base = 1.08 * (impact + exploitability)
	} else {
		base = impact + exploitability
	}

	if base > 10 {
		base = 10
	}

	base = roundup(base)
	return base
}

func metricVal(metrics map[string]string, key string, vals map[string]float64) float64 {
	v, ok := metrics[key]
	if !ok {
		return 0
	}
	return vals[v]
}

var impactVals = map[string]float64{"H": 0.56, "L": 0.22, "N": 0}

func pow(x float64, n int) float64 {
	r := 1.0
	for i := 0; i < n; i++ {
		r *= x
	}
	return r
}

func roundup(x float64) float64 {
	return math.Ceil(x*10) / 10
}

func severityFromScore(score float64) scanner.Severity {
	switch {
	case score >= 9.0:
		return scanner.SeverityCritical
	case score >= 7.0:
		return scanner.SeverityHigh
	case score >= 4.0:
		return scanner.SeverityMedium
	case score > 0:
		return scanner.SeverityLow
	default:
		return scanner.SeverityUnknown
	}
}

func normalizeOSVSeverity(s string) scanner.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return scanner.SeverityCritical
	case "HIGH":
		return scanner.SeverityHigh
	case "MEDIUM":
		return scanner.SeverityMedium
	case "LOW":
		return scanner.SeverityLow
	default:
		return scanner.SeverityUnknown
	}
}
