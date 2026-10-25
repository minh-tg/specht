package grype

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
	"github.com/minh-tg/specht/internal/scanner"
)

type grypeDoc struct {
	Matches    []grypeMatch `json:"matches"`
	Source     grypeSource  `json:"source"`
	Descriptor struct {
		Configuration json.RawMessage `json:"configuration"`
	} `json:"descriptor"`
}

type grypeMatch struct {
	Vulnerability          grypeVuln          `json:"vulnerability"`
	RelatedVulnerabilities []grypeRelatedVuln `json:"relatedVulnerabilities"`
	MatchDetails           []grypeMatchDetail `json:"matchDetails"`
	Artifact               grypeArtifact      `json:"artifact"`
}

type grypeVuln struct {
	ID          string      `json:"id"`
	DataSource  string      `json:"dataSource"`
	Namespace   string      `json:"namespace"`
	Severity    string      `json:"severity"`
	URLs        []string    `json:"urls"`
	Description string      `json:"description"`
	CVSS        []grypeCVSS `json:"cvss"`
	Fix         *grypeFix   `json:"fix"`
	Advisories  []grypeAdv  `json:"advisories"`
}

type grypeCVSS struct {
	Source  string           `json:"source"`
	Type    string           `json:"type"`
	Version string           `json:"version"`
	Vector  string           `json:"vector"`
	Metrics grypeCVSSMetrics `json:"metrics"`
}

type grypeCVSSMetrics struct {
	BaseScore float64 `json:"baseScore"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
	State    string   `json:"state"`
}

type grypeAdv struct {
	ID   string `json:"id"`
	Link string `json:"link"`
}

type grypeRelatedVuln struct {
	ID          string      `json:"id"`
	DataSource  string      `json:"dataSource"`
	Namespace   string      `json:"namespace"`
	Severity    string      `json:"severity"`
	URLs        []string    `json:"urls"`
	Description string      `json:"description"`
	CVSS        []grypeCVSS `json:"cvss"`
}

type grypeMatchDetail struct {
	Type    string `json:"type"`
	Matcher string `json:"matcher"`
}

type grypeArtifact struct {
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Type      string          `json:"type"`
	Locations []grypeLocation `json:"locations"`
	Language  string          `json:"language"`
	Licenses  []string        `json:"licenses"`
	PURL      string          `json:"purl"`
	Upstreams []grypeUpstream `json:"upstreams"`
}

type grypeLocation struct {
	Path string `json:"path"`
}

type grypeUpstream struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Scanner adapts grype JSON output to the normalized scanner model.
type Scanner struct{}

// NewScanner builds the grype adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:        "grype",
		DisplayName: "Grype",
		Formats: []scanner.Format{
			{
				Name:       "JSON",
				Extensions: []string{".json"},
				Command:    `grype dir:. -o json > grype.json`,
				TestedWith: "Grype 0.120.1",
				Note:       "Its CycloneDX output (`-o cyclonedx-json`) goes to the SBOM scanner.",
			},
		},
		Version:               "0.7",
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          []scanner.FindingKind{"sca"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeFilesystem, domain.ScanTypeImage},
		ProvidesPackages:      true,
		SupportsAutoDetection: true,
	}
}

func (s *Scanner) DetectFormat(data []byte) bool {
	return s.Recognize(data) == scanner.Definite
}

// Recognize grades a document. Grype names itself in its descriptor, so even
// a scan with no matches is definite; a bare matches list is only possible.
func (s *Scanner) Recognize(data []byte) scanner.Recognition {
	shape, ok := parseutil.ReadShape(data)
	if !ok || !shape.IsObject() {
		return scanner.NotRecognized
	}
	var descriptor struct {
		Name string `json:"name"`
	}
	if raw, has := shape.Object["descriptor"]; has && json.Unmarshal(raw, &descriptor) == nil && descriptor.Name == "grype" {
		return scanner.Definite
	}
	matches, present := shape.List("matches")
	if !present {
		return scanner.NotRecognized
	}
	if len(matches) == 0 {
		return scanner.Possible
	}
	if parseutil.ObjectHas(matches[0], "vulnerability") {
		return scanner.Definite
	}
	return scanner.NotRecognized
}

// findingArrays names the arrays of a document that carry findings and
// packages (see scanner.CheckDocument).
var findingArrays = []string{"matches"}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	budget, err := parseutil.NewBudget(ctx, data, findingArrays...)
	if err != nil {
		return nil, err
	}
	if s.Recognize(data) == scanner.NotRecognized {
		return nil, scanner.Unrecognized("grype")
	}
	var doc grypeDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, scanner.Malformed("grype", err)
	}

	return parseutil.Hardened(convert(budget, doc))
}

func convert(budget *parseutil.Budget, doc grypeDoc) (*domain.NormalizedReport, error) {
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeFilesystem,
		Findings:           nil,
	}

	if unfiltered(doc.Descriptor.Configuration) {
		// The run's own configuration shows nothing hid a match, so a
		// vulnerability absent from it was looked for and is gone.
		nr.Completeness = domain.CompletenessComplete
		nr.CoveredFindingKinds = []string{"sca"}
	}

	if target, scanType, ok := sourceIdentity(doc.Source); ok {
		// The source is in every report, clean or not, so it keeps the scan
		// scope the same across scans and lets a clean scan close findings.
		nr.Target = &target
		nr.ScanType = scanType
	} else if len(doc.Matches) > 0 && len(doc.Matches[0].Artifact.Locations) > 0 {
		// A report without a source can only name the target from where its
		// first match was found.
		loc := doc.Matches[0].Artifact.Locations[0]
		nr.Target = &domain.TargetInfo{
			Kind:       "filesystem",
			Identifier: loc.Path,
		}
	}

	// Grype's standard JSON output only reports matched artifacts, i.e.
	// packages that carry at least one vulnerability. The package inventory is
	// therefore limited to those artifacts; projects that need a complete
	// dependency tree should pair grype with a syft SBOM scan.
	packages, err := collectPackages(budget, doc.Matches)
	if err != nil {
		return nil, err
	}
	nr.Packages = packages
	for _, match := range doc.Matches {
		if err := budget.Add(1); err != nil {
			return nil, err
		}
		nr.Findings = append(nr.Findings, parseutil.HardenFinding(convertMatch(match)))
	}

	return nr, nil
}

// collectPackages deduplicates matched artifacts into package refs by PURL.
func collectPackages(budget *parseutil.Budget, matches []grypeMatch) ([]domain.PackageRef, error) {
	seen := make(map[string]struct{})
	var packages []domain.PackageRef
	for _, match := range matches {
		artifact := match.Artifact
		purl := domain.NormalizePURL(artifact.PURL)
		if purl == "" {
			continue
		}
		if _, ok := seen[purl]; ok {
			continue
		}
		seen[purl] = struct{}{}
		if err := budget.Add(1); err != nil {
			return nil, err
		}

		manifestPath := ""
		if len(artifact.Locations) > 0 {
			manifestPath = parseutil.CleanFilePath(artifact.Locations[0].Path)
		}
		pkgType, _, _ := domain.SplitPURL(purl)

		packages = append(packages, parseutil.HardenPackage(domain.PackageRef{
			PURL:         purl,
			Ecosystem:    pkgType,
			Name:         artifact.Name,
			Version:      artifact.Version,
			ManifestPath: manifestPath,
		}))
	}
	return packages, nil
}

// convertMatch maps a single grype match to a normalized SCA finding.
func convertMatch(match grypeMatch) domain.NormalizedFinding {
	vuln := match.Vulnerability
	artifact := match.Artifact
	purl := artifact.PURL

	score, cvssVec, cvssVer := pickCVSS(vuln.CVSS)
	aliases := extractAliases(match.RelatedVulnerabilities)

	// If no CVSS on primary, check relatedVulnerabilities
	if score == 0 {
		score, cvssVec, cvssVer = relatedCVSS(match.RelatedVulnerabilities)
	}

	var cvss *domain.CVSSInfo
	if cvssVec != "" {
		cvss = &domain.CVSSInfo{
			Version: cvssVer,
			Vector:  cvssVec,
			Score:   score,
		}
	}

	var fix *domain.FixInfo
	if vuln.Fix != nil && len(vuln.Fix.Versions) > 0 {
		fix = &domain.FixInfo{Summary: strings.Join(vuln.Fix.Versions, ", ")}
	}

	dims := []domain.Dimension{
		{Key: "vulnerability_id", Value: vuln.ID},
		{Key: "package_name", Value: artifact.Name},
		{Key: "installed_version", Value: artifact.Version},
		{Key: "purl", Value: purl},
	}
	if fix != nil && len(vuln.Fix.Versions) > 0 {
		// The dimension is one concrete version for the patch proposal; the
		// human-readable Fix.Summary keeps the scanner's full list.
		dims = append(dims, domain.Dimension{Key: "fixed_version", Value: vuln.Fix.Versions[0]})
	}

	location := ""
	if len(artifact.Locations) > 0 {
		location = parseutil.CleanFilePath(artifact.Locations[0].Path)
	}

	return domain.NormalizedFinding{
		Fingerprint: string(domain.SCAFingerprint(vuln.ID, purl)),
		FindingKind: "sca",
		Title:       vuln.ID + " in " + artifact.Name,
		Description: vuln.Description,
		Severity:    normalizeGrypeSeverity(vuln.Severity),
		Score:       score,
		Location:    domain.SCALocation(artifact.Name, artifact.Version, location),
		Resource:    artifact.Name + "@" + artifact.Version,
		Aliases:     aliases,
		CVSS:        cvss,
		CVSSAll:     cvssRecords(vuln.CVSS, match.RelatedVulnerabilities),
		Fix:         fix,
		Dimensions:  dims,
		Extensions: map[string]any{
			"package": map[string]any{
				"name":    artifact.Name,
				"version": artifact.Version,
				"type":    artifact.Type,
			},
			"namespace":     vuln.Namespace,
			"severity_raw":  vuln.Severity,
			"purl":          purl,
			"artifact_type": artifact.Type,
			"language":      artifact.Language,
		},
	}
}

// cvssRecords keeps every scored CVSS entry of the matched vulnerability, or
// of its related vulnerabilities when the match carries none of its own, the
// same fallback pickCVSS uses. The source is the one grype prints, with the
// entry type (primary or secondary) appended when the report gives it.
func cvssRecords(own []grypeCVSS, related []grypeRelatedVuln) []domain.CVSSRecord {
	out := appendCVSSRecords(nil, own)
	if len(out) > 0 {
		return out
	}
	for _, rv := range related {
		out = appendCVSSRecords(out, rv.CVSS)
	}
	return out
}

func appendCVSSRecords(out []domain.CVSSRecord, list []grypeCVSS) []domain.CVSSRecord {
	for _, c := range list {
		if c.Metrics.BaseScore <= 0 {
			continue
		}
		source := strings.ToLower(strings.TrimSpace(c.Source))
		if kind := strings.ToLower(strings.TrimSpace(c.Type)); source != "" && kind != "" {
			source += ":" + kind
		}
		if rec, ok := parseutil.NewCVSSRecord(c.Vector, c.Metrics.BaseScore, source); ok {
			out = parseutil.AddCVSS(out, rec)
		}
	}
	return out
}

func pickCVSS(cvssList []grypeCVSS) (score float64, vector string, version string) {
	for _, c := range cvssList {
		if c.Metrics.BaseScore > 0 {
			return c.Metrics.BaseScore, c.Vector, c.Version
		}
	}
	return 0, "", ""
}

// relatedCVSS falls back to the first related vulnerability that carries a
// usable CVSS score.
func relatedCVSS(related []grypeRelatedVuln) (score float64, vector string, version string) {
	for _, rv := range related {
		if len(rv.CVSS) == 0 {
			continue
		}
		s, vec, ver := pickCVSS(rv.CVSS)
		if s > 0 {
			return s, vec, ver
		}
	}
	return 0, "", ""
}

func extractAliases(related []grypeRelatedVuln) []string {
	var aliases []string
	for _, rv := range related {
		aliases = append(aliases, rv.ID)
	}
	return aliases
}

func normalizeGrypeSeverity(s string) domain.Severity {
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
