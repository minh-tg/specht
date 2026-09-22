package osvscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xMinhx/specht/internal/cvss"
	"github.com/xMinhx/specht/internal/domain"
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

// Scanner adapts osv-scanner JSON output to the normalized scanner model.
type Scanner struct{}

// NewScanner builds the osv-scanner adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:                  "osv-scanner",
		Version:               "1",
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          []scanner.FindingKind{"sca"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeLockfile, domain.ScanTypeSBOM, domain.ScanTypeRepository, domain.ScanTypeImage, domain.ScanTypeFilesystem},
		ProvidesPackages:      true,
		SupportsAutoDetection: true,
	}
}

func (s *Scanner) DetectFormat(data []byte) bool {
	var probe osvReport
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return len(probe.Results) > 0
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	var report osvReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("osv-scanner: parse json: %w", err)
	}

	return convert(report), nil
}

func convertToScanType(s string) domain.ScanType {
	switch s {
	case "lockfile":
		return domain.ScanTypeLockfile
	case "sbom":
		return domain.ScanTypeSBOM
	case "repository", "git":
		return domain.ScanTypeRepository
	case "image":
		return domain.ScanTypeImage
	case "filesystem":
		return domain.ScanTypeFilesystem
	case "iac":
		return domain.ScanTypeIaC
	default:
		return domain.ScanTypeLockfile
	}
}

func convert(report osvReport) *domain.NormalizedReport {
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		Findings:           nil,
	}

	for _, result := range report.Results {
		if nr.ScanType == "" {
			nr.ScanType = convertToScanType(result.Source.Type)
		}
		nr.Target = &domain.TargetInfo{
			Kind:       result.Source.Type,
			Identifier: result.Source.Path,
		}

		// full package inventory, vulnerable or not
		addOsvPackages(nr, result)
		addOsvVulns(nr, result)
	}

	return nr
}

func addOsvPackages(nr *domain.NormalizedReport, result osvResult) {
	for _, pkg := range result.Packages {
		purl := pkg.Package.PURL
		if purl == "" {
			purl = "pkg:" + strings.ToLower(pkg.Package.Ecosystem) + "/" + pkg.Package.Name
		}
		nr.Packages = append(nr.Packages, domain.PackageRef{
			PURL:         domain.NormalizePURL(purl),
			Ecosystem:    pkg.Package.Ecosystem,
			Name:         pkg.Package.Name,
			Version:      pkg.Package.Version,
			ManifestPath: result.Source.Path,
		})
	}
}

func addOsvVulns(nr *domain.NormalizedReport, result osvResult) {
	for _, pkg := range result.Packages {
		groupAnalysis := make(map[string]osvCallAnalysis, len(pkg.Groups))
		for _, g := range pkg.Groups {
			for id, analysis := range g.ExperimentalAnalysis {
				groupAnalysis[id] = analysis
			}
		}

		for _, v := range pkg.Vulnerabilities {
			f := osvFinding{
				vuln:     v,
				pkg:      pkg.Package,
				source:   result.Source,
				analysis: groupAnalysis[v.ID],
			}
			nr.Findings = append(nr.Findings, f.normalized())
		}
	}
}

// osvFinding is the per-vulnerability conversion context for one OSV
// vulnerability entry.
type osvFinding struct {
	vuln     osvVuln
	pkg      osvPkg
	source   osvSource
	analysis osvCallAnalysis
}

// normalized converts one OSV vulnerability into a NormalizedFinding.
func (f osvFinding) normalized() domain.NormalizedFinding {
	v := f.vuln
	purl := f.pkg.PURL
	if v.Affected != nil && v.Affected.Package.PURL != "" {
		purl = v.Affected.Package.PURL
	}
	if purl == "" {
		ecosystem, name := f.pkg.Ecosystem, f.pkg.Name
		if v.Affected != nil {
			ecosystem, name = v.Affected.Package.Ecosystem, v.Affected.Package.Name
		}
		purl = "pkg:" + strings.ToLower(ecosystem) + "/" + name
	}

	fixedVersion := firstFixedVersion(v)
	cveID := firstCVEAlias(v)

	var reachability *domain.ReachabilityHint
	if f.analysis.Called != nil {
		var state domain.ReachabilityState
		if *f.analysis.Called {
			state = domain.ReachabilityReachable
		} else {
			state = domain.ReachabilityNotReachable
		}
		reachability = &domain.ReachabilityHint{
			State:    state,
			Source:   "osv",
			Evidence: "osv-scanner experimental call analysis",
		}
	}

	fix := fixInfo(v, fixedVersion)

	ext := map[string]any{
		"source_path": f.source.Path,
		"ecosystem":   f.pkg.Ecosystem,
		"osv_id":      v.ID,
		"aliases":     v.Aliases,
		"published":   v.Published,
		"modified":    v.Modified,
	}
	if cveID != "" {
		ext["cve_id"] = cveID
	}
	if f.analysis.Called != nil {
		ext["call_analysis"] = *f.analysis.Called
	}

	dims := []domain.Dimension{
		{Key: "vulnerability_id", Value: v.ID},
		{Key: "package_name", Value: f.pkg.Name},
		{Key: "ecosystem", Value: f.pkg.Ecosystem},
		{Key: "installed_version", Value: f.pkg.Version},
		{Key: "purl", Value: purl},
	}
	if fixedVersion != "" {
		dims = append(dims, domain.Dimension{Key: "fixed_version", Value: fixedVersion})
	}

	return domain.NormalizedFinding{
		Fingerprint:  string(domain.SCAFingerprint(v.ID, purl)),
		FindingKind:  "sca",
		Title:        v.Summary,
		Description:  v.Details,
		Severity:     extractSeverity(v),
		Score:        extractScore(v),
		Location:     f.source.Path + ":" + f.pkg.Name,
		Aliases:      v.Aliases,
		Reachability: reachability,
		CVSS:         extractCVSSInfo(v),
		Fix:          fix,
		Dimensions:   dims,
		Extensions:   ext,
	}
}

// firstFixedVersion returns the last fixed version recorded across the
// vulnerability's affected ranges, or "" when none is fixed.
func firstFixedVersion(v osvVuln) string {
	if v.Affected == nil {
		return ""
	}
	var fixed string
	for _, rng := range v.Affected.Ranges {
		for _, e := range rng.Events {
			if e.Fixed != "" {
				fixed = e.Fixed
			}
		}
	}
	return fixed
}

// firstCVEAlias returns the first CVE- alias of a vulnerability, if any.
func firstCVEAlias(v osvVuln) string {
	for _, alias := range v.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return ""
}

// fixInfo builds the FixInfo from a fixed version and the first reference
// URL.
func fixInfo(v osvVuln, fixedVersion string) *domain.FixInfo {
	if fixedVersion == "" {
		return nil
	}
	fix := &domain.FixInfo{Summary: fixedVersion}
	for _, ref := range v.References {
		if fix.URL == "" {
			fix.URL = ref.URL
		}
	}
	return fix
}

func extractCVSSInfo(v osvVuln) *domain.CVSSInfo {
	for _, s := range v.Severity {
		var version string
		switch s.Type {
		case "CVSS_V4":
			version = "4.0"
		case "CVSS_V3":
			version = "3.1"
		case "CVSS_V2":
			version = "2.0"
		default:
			continue
		}
		score, _, ok := parseCVSSScore(s.Score)
		if ok {
			return &domain.CVSSInfo{
				Version: version,
				Vector:  s.Score,
				Score:   score,
			}
		}
	}
	return nil
}

func extractSeverity(v osvVuln) domain.Severity {
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
	return domain.SeverityUnknown
}

// scoreForSeverityType returns the first parseable score for one severity
// type across the vulnerability's severity entries.
func scoreForSeverityType(v osvVuln, typ string) (float64, bool) {
	for _, s := range v.Severity {
		if s.Type != typ {
			continue
		}
		if score, _, ok := parseCVSSScore(s.Score); ok {
			return score, true
		}
	}
	return 0, false
}

func extractScore(v osvVuln) float64 {
	for _, typ := range []string{"CVSS_V4", "CVSS_V3", "CVSS_V2"} {
		if score, ok := scoreForSeverityType(v, typ); ok {
			return score
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

func severityFromScore(score float64) domain.Severity {
	switch {
	case score >= 9.0:
		return domain.SeverityCritical
	case score >= 7.0:
		return domain.SeverityHigh
	case score >= 4.0:
		return domain.SeverityMedium
	case score > 0:
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}

func normalizeOSVSeverity(s string) domain.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return domain.SeverityCritical
	case "HIGH":
		return domain.SeverityHigh
	case "MEDIUM":
		return domain.SeverityMedium
	case "LOW":
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}
