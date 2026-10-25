package osvscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/minh-tg/specht/internal/cvss"
	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
	"github.com/minh-tg/specht/internal/scanner"
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
	ID               string             `json:"id"`
	Aliases          []string           `json:"aliases"`
	Summary          string             `json:"summary"`
	Details          string             `json:"details"`
	Published        string             `json:"published"`
	Modified         string             `json:"modified"`
	Severity         []osvSeverity      `json:"severity"`
	DatabaseSpecific *osvDBSpecific     `json:"database_specific"`
	Affected         osvAffectedRecords `json:"affected"`
	References       []osvReference     `json:"references"`
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

// osvAffectedRecords accepts the OSV array and older scanner object format.
type osvAffectedRecords []osvAffected

func (a *osvAffectedRecords) UnmarshalJSON(data []byte) error {
	var records []osvAffected
	if strings.HasPrefix(strings.TrimSpace(string(data)), "[") {
		if err := json.Unmarshal(data, &records); err != nil {
			return err
		}
	} else {
		var record *osvAffected
		if err := json.Unmarshal(data, &record); err != nil {
			return err
		}
		if record != nil {
			records = append(records, *record)
		}
	}
	*a = records
	return nil
}

func (a osvAffectedRecords) forPackage(pkg osvPkg) *osvAffected {
	for i := range a {
		if a[i].Package.Name == pkg.Name && strings.EqualFold(a[i].Package.Ecosystem, pkg.Ecosystem) {
			return &a[i]
		}
	}
	return nil
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
		Name:        "osv-scanner",
		DisplayName: "OSV-Scanner",
		Formats: []scanner.Format{
			{
				Name:       "JSON",
				Extensions: []string{".json"},
				Command:    `osv-scanner scan source --format json --output-file osv.json .`,
				TestedWith: "OSV-Scanner 2.6.0",
			},
		},
		Version:               "1",
		ContractVersion:       1,
		FingerprintVersion:    fingerprintVersion,
		FindingKinds:          []scanner.FindingKind{"sca"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeLockfile, domain.ScanTypeSBOM, domain.ScanTypeRepository, domain.ScanTypeImage, domain.ScanTypeFilesystem},
		ProvidesPackages:      true,
		SupportsAutoDetection: true,
	}
}

func (s *Scanner) DetectFormat(data []byte) bool {
	return s.Recognize(data) == scanner.Definite
}

// Recognize grades a document. OSV-Scanner output is an object whose results
// list holds sources with packages; an empty list is possible because other
// tools also write one, so a named OSV-Scanner upload may still be a clean scan.
func (s *Scanner) Recognize(data []byte) scanner.Recognition {
	shape, ok := parseutil.ReadShape(data)
	if !ok || !shape.IsObject() {
		return scanner.NotRecognized
	}
	results, present := shape.List("results")
	if !present {
		return scanner.NotRecognized
	}
	for _, r := range results {
		if parseutil.ObjectHas(r, "source") || parseutil.ObjectHas(r, "packages") {
			return scanner.Definite
		}
	}
	if len(results) == 0 {
		return scanner.Possible
	}
	return scanner.NotRecognized
}

// findingArrays names the arrays of a document that carry findings and
// packages (see scanner.CheckDocument).
var findingArrays = []string{"results", "packages", "vulnerabilities"}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	budget, err := parseutil.NewBudget(ctx, data, findingArrays...)
	if err != nil {
		return nil, err
	}
	if s.Recognize(data) == scanner.NotRecognized {
		return nil, scanner.Unrecognized("osv-scanner")
	}
	var report osvReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, scanner.Malformed("osv-scanner", err)
	}

	return parseutil.Hardened(convert(budget, report))
}

func targetKindForSource(sourceType string) string {
	switch strings.ToLower(strings.TrimSpace(sourceType)) {
	case "repository", "git":
		return "repo"
	case "image":
		return "container_image"
	case "filesystem":
		return "filesystem"
	case "iac":
		return "iac_stack"
	case "lockfile", "sbom":
		return "package"
	default:
		// OSV results primarily describe package inventory; retain unknown
		// upstream source types separately rather than persisting them as a
		// target kind outside the database vocabulary.
		return "package"
	}
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

func convert(budget *parseutil.Budget, report osvReport) (*domain.NormalizedReport, error) {
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: fingerprintVersion,
		Completeness:       domain.CompletenessUnknown,
		ScanScope:          &domain.ScanScope{Ext: make(map[string]string)},
		Findings:           nil,
	}

	for _, result := range report.Results {
		if nr.ScanType == "" {
			nr.ScanType = convertToScanType(result.Source.Type)
		}
		nr.Target = &domain.TargetInfo{
			Kind:       targetKindForSource(result.Source.Type),
			Identifier: result.Source.Path,
		}
		nr.ScanScope.Ext["osv_source_type"] = result.Source.Type
		nr.ScanScope.Ext["osv_source_path"] = result.Source.Path

		// full package inventory, vulnerable or not
		if err := addOsvPackages(budget, nr, result); err != nil {
			return nil, err
		}
		if err := addOsvVulns(budget, nr, result); err != nil {
			return nil, err
		}
	}
	// A clean scan has no results to name its source type, but the report still
	// needs one to be stored. OSV-Scanner reads lockfiles unless told otherwise.
	if nr.ScanType == "" {
		nr.ScanType = domain.ScanTypeLockfile
	}

	return nr, nil
}

func addOsvPackages(budget *parseutil.Budget, nr *domain.NormalizedReport, result osvResult) error {
	manifestPath := parseutil.CleanFilePath(result.Source.Path)
	for _, pkg := range result.Packages {
		if err := budget.Add(1); err != nil {
			return err
		}
		pkg.Package = pkg.Package.withGoVersion()
		nr.Packages = append(nr.Packages, parseutil.HardenPackage(domain.PackageRef{
			PURL:         pkg.Package.purl(advisoryPURL(pkg)),
			Ecosystem:    pkg.Package.Ecosystem,
			Name:         pkg.Package.Name,
			Version:      pkg.Package.Version,
			ManifestPath: manifestPath,
		}))
	}
	return nil
}

func addOsvVulns(budget *parseutil.Budget, nr *domain.NormalizedReport, result osvResult) error {
	for _, pkg := range result.Packages {
		pkg.Package = pkg.Package.withGoVersion()
		groupAnalysis := make(map[string]osvCallAnalysis, len(pkg.Groups))
		for _, g := range pkg.Groups {
			for id, analysis := range g.ExperimentalAnalysis {
				groupAnalysis[id] = analysis
			}
		}

		for _, v := range pkg.Vulnerabilities {
			if err := budget.Add(1); err != nil {
				return err
			}
			f := osvFinding{
				vuln:     v,
				pkg:      pkg.Package,
				source:   result.Source,
				affected: v.Affected.forPackage(pkg.Package),
				analysis: groupAnalysis[v.ID],
			}
			nr.Findings = append(nr.Findings, parseutil.HardenFinding(f.normalized()))
		}
	}
	return nil
}

// osvFinding is the per-vulnerability conversion context for one OSV
// vulnerability entry.
type osvFinding struct {
	vuln     osvVuln
	pkg      osvPkg
	source   osvSource
	affected *osvAffected
	analysis osvCallAnalysis
}

// normalized converts one OSV vulnerability into a NormalizedFinding.
func (f osvFinding) normalized() domain.NormalizedFinding {
	v := f.vuln
	purl := f.installedPURL()

	fixedVersion := firstFixedVersion(f.affected)
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
	cleanSource := parseutil.CleanFilePath(f.source.Path)

	ext := map[string]any{
		"source_path": cleanSource,
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
		Location:     domain.SCALocation(f.pkg.Name, f.pkg.Version, cleanSource),
		Aliases:      v.Aliases,
		Reachability: reachability,
		CVSS:         extractCVSSInfo(v),
		CVSSAll:      extractCVSSAll(v),
		Fix:          fix,
		Dimensions:   dims,
		Extensions:   ext,
	}
}

// fingerprintVersion is the version of this scanner's identity formula.
// Version 2 keys a finding on the installed version of the package, so
// lodash 4.17.20 and 4.17.15 are two findings, and spells a Go module
// version with its leading "v" as Grype and Trivy do. Version 1 took the
// advisory's unversioned purl and merged them. Version 3 builds the purl of a
// package that has none from the ecosystem's purl type (golang, cargo, gem,
// composer and so on) where version 2 used the lowercased OSV ecosystem name.
const fingerprintVersion = 3

// installedPURL is the purl of the scanned package at its installed version
// (see osvPkg.purl), the purl every other SCA adapter keys a finding on.
func (f osvFinding) installedPURL() string {
	advisory := ""
	if f.affected != nil {
		advisory = f.affected.Package.PURL
	}
	return f.pkg.purl(advisory)
}

// advisoryPURL is the purl of the first affected package that one of the
// package's vulnerabilities names for it, or "". The inventory entry has no
// finding of its own to ask, and a finding uses its own advisory's.
func advisoryPURL(pkg osvPkgResult) string {
	for _, v := range pkg.Vulnerabilities {
		if a := v.Affected.forPackage(pkg.Package); a != nil && a.Package.PURL != "" {
			return a.Package.PURL
		}
	}
	return ""
}

// withGoVersion spells a Go module version the way Go, Grype and Trivy do,
// with a leading "v". OSV-Scanner writes 1.3.1 where they write v1.3.1, so
// without this the same module version became two purls and two findings
// when a project ran OSV-Scanner next to Grype or Trivy. A version that
// already starts with "v", or with anything but a digit, is kept, as is any
// other ecosystem. A purl that carries the old spelling is rewritten too.
func (p osvPkg) withGoVersion() osvPkg {
	if !strings.EqualFold(p.Ecosystem, "Go") || p.Version == "" || p.Version[0] < '0' || p.Version[0] > '9' {
		return p
	}
	old := p.Version
	p.Version = "v" + old
	if purl := domain.NormalizePURL(p.PURL); strings.HasSuffix(purl, "@"+old) {
		p.PURL = strings.TrimSuffix(purl, "@"+old) + "@" + p.Version
	}
	return p
}

// firstFixedVersion returns the last fixed version recorded across the
// vulnerability's affected ranges, or "" when none is fixed.
func firstFixedVersion(affected *osvAffected) string {
	if affected == nil {
		return ""
	}
	var fixed string
	for _, rng := range affected.Ranges {
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
			// The OSV type CVSS_V3 covers 3.0 and 3.1, so the prefix decides.
			if rec, found := parseutil.NewCVSSRecord(s.Score, 0, ""); found {
				version = rec.Version
			}
			return &domain.CVSSInfo{
				Version: version,
				Vector:  s.Score,
				Score:   score,
			}
		}
	}
	return nil
}

// extractCVSSAll keeps every severity entry that carries a scorable CVSS
// vector. The version comes from the vector prefix, because the OSV type
// CVSS_V3 covers both 3.0 and 3.1 vectors. OSV names no scoring source.
func extractCVSSAll(v osvVuln) []domain.CVSSRecord {
	var out []domain.CVSSRecord
	for _, s := range v.Severity {
		switch s.Type {
		case "CVSS_V4", "CVSS_V3", "CVSS_V2":
		default:
			continue
		}
		rec, ok := parseutil.NewCVSSRecord(s.Score, 0, "")
		if !ok {
			continue
		}
		score, err := cvss.Calculate(rec.Vector)
		if err != nil || score <= 0 {
			continue
		}
		rec.Score = score
		out = parseutil.AddCVSS(out, rec)
	}
	return out
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
	case "MEDIUM", "MODERATE":
		return domain.SeverityMedium
	case "LOW":
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}
