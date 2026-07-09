package osvscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/xMinhx/specht/internal/cvss"
	"github.com/xMinhx/specht/internal/scanner"
)

type osvReport struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource      `json:"source"`
	Packages []osvPkgResult `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
	Type string `json:"type"`
}

type osvPkgResult struct {
	Package         osvPkg     `json:"package"`
	Vulnerabilities []osvVuln  `json:"vulnerabilities"`
	Groups          []osvGroup `json:"groups"`
}

type osvPkg struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	PURL      string `json:"purl"`
}

type osvVuln struct {
	ID               string         `json:"id"`
	Aliases          []string       `json:"aliases"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Published        string         `json:"published"`
	Modified         string         `json:"modified"`
	Severity         []osvSeverity  `json:"severity"`
	DatabaseSpecific *osvDBSpecific `json:"database_specific"`
	Affected         *osvAffected   `json:"affected"`
	References       []osvReference `json:"references"`
}

type osvSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type osvDBSpecific struct {
	Severity string `json:"severity"`
}

type osvAffected struct {
	Package  osvPkg     `json:"package"`
	Ranges   []osvRange `json:"ranges"`
	Versions []string   `json:"versions"`
}

type osvRange struct {
	Type   string          `json:"type"`
	Events []osvRangeEvent `json:"events"`
}

type osvRangeEvent struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
}

type osvReference struct {
	URL string `json:"url"`
}

type osvGroup struct {
	IDs                  []string                   `json:"ids"`
	ExperimentalAnalysis map[string]osvCallAnalysis `json:"experimentalAnalysis"`
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

func convertToScanType(s string) scanner.ScanType {
	switch s {
	case "lockfile":
		return scanner.ScanTypeLockfile
	case "sbom":
		return scanner.ScanTypeSBOM
	case "repository", "git":
		return scanner.ScanTypeRepository
	case "image":
		return scanner.ScanTypeImage
	case "filesystem":
		return scanner.ScanTypeFilesystem
	case "iac":
		return scanner.ScanTypeIaC
	default:
		return scanner.ScanTypeLockfile
	}
}

func convert(report osvReport) *scanner.NormalizedReport {
	nr := &scanner.NormalizedReport{
		ScannerName: "osv-scanner",
		Findings:    nil,
		ScanScope:   make(map[string]any),
	}

	for _, result := range report.Results {
		if nr.ScanType == "" {
			nr.ScanType = convertToScanType(result.Source.Type)
		}
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
					"osv_id":    v.ID,
					"ecosystem": pkg.Package.Ecosystem,
					"aliases":   aliases,
					"published": v.Published,
					"modified":  v.Modified,
				}

				if analysis, ok := groupAnalysis[v.ID]; ok && analysis.Called != nil {
					meta["call_analysis"] = *analysis.Called
				}

				title := v.Summary
				desc := v.Details

				nr.Findings = append(nr.Findings, scanner.NormalizedFinding{
					Fingerprint: fingerprint,
					FindingKind: "sca",
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
		if s.Type == "CVSS_V4" || s.Type == "CVSS_V3" || s.Type == "CVSS_V2" {
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
		if s.Type == "CVSS_V4" {
			score, _, ok := parseCVSSScore(s.Score)
			if ok {
				return score
			}
		}
	}
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
		score, err := cvss.Calculate(s)
		if err == nil && score > 0 {
			return score, s, true
		}
		return 0, s, false
	}

	if looksLikeCVSSv2Vector(s) {
		full := "CVSS:2.0/" + s
		score, err := cvss.Calculate(full)
		if err == nil && score > 0 {
			return score, full, true
		}
	}

	var score float64
	if _, err := fmt.Sscanf(s, "%f", &score); err == nil {
		return score, s, true
	}
	return 0, s, false
}

func looksLikeCVSSv2Vector(s string) bool {
	return strings.HasPrefix(s, "AV:") || strings.HasPrefix(s, "AC:") || strings.HasPrefix(s, "Au:")
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
