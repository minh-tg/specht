package dependencycheck

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
	"github.com/minh-tg/specht/internal/scanner"
)

type dcReport struct {
	ReportSchema string         `json:"reportSchema"`
	Dependencies []dcDependency `json:"dependencies"`
}

type dcDependency struct {
	FileName        string            `json:"fileName"`
	FilePath        string            `json:"filePath"`
	Packages        []dcPackage       `json:"packages"`
	Vulnerabilities []dcVulnerability `json:"vulnerabilities"`
}

type dcPackage struct {
	ID string `json:"id"`
}

type dcVulnerability struct {
	Name        string  `json:"name"`
	Severity    string  `json:"severity"`
	Source      string  `json:"source"`
	CvssV3      *dcCvss `json:"cvssv3"`
	CvssV2      *dcCvss `json:"cvssv2"`
	Description string  `json:"description"`
	References  []dcRef `json:"references"`
}

type dcCvss struct {
	BaseScore    float64 `json:"baseScore"`
	Score        float64 `json:"score"`
	VectorString string  `json:"vectorString"`
}

type dcRef struct {
	URL string `json:"url"`
}

// Scanner adapts OWASP Dependency-Check JSON output to the normalized scanner model.
type Scanner struct{}

// NewScanner builds the Dependency-Check adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:        "dependency-check",
		DisplayName: "OWASP Dependency-Check",
		Formats: []scanner.Format{
			{
				Name:       "JSON",
				Extensions: []string{".json"},
				Command:    `dependency-check --scan . --format JSON --out .`,
				TestedWith: "Dependency-Check 12.1.0",
			},
		},
		Version:               "2",
		ContractVersion:       1,
		FingerprintVersion:    fingerprintVersion,
		FindingKinds:          []scanner.FindingKind{"sca"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeFilesystem},
		ProvidesPackages:      true,
		SupportsAutoDetection: true,
	}
}

func (s *Scanner) DetectFormat(data []byte) bool {
	return s.Recognize(data) == scanner.Definite
}

// Recognize grades a document. Dependency-Check writes a report schema in
// every report; scan info with a dependency list is possible without it.
func (s *Scanner) Recognize(data []byte) scanner.Recognition {
	shape, ok := parseutil.ReadShape(data)
	if !ok || !shape.IsObject() {
		return scanner.NotRecognized
	}
	if shape.String("reportSchema") != "" {
		return scanner.Definite
	}
	if shape.Has("scanInfo") && shape.Has("dependencies") {
		return scanner.Possible
	}
	return scanner.NotRecognized
}

// findingArrays names the arrays of a document that carry findings and
// packages (see scanner.CheckDocument).
var findingArrays = []string{"dependencies", "packages", "vulnerabilities"}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	budget, err := parseutil.NewBudget(ctx, data, findingArrays...)
	if err != nil {
		return nil, err
	}
	if s.Recognize(data) == scanner.NotRecognized {
		return nil, scanner.Unrecognized("dependency-check")
	}
	var report dcReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, scanner.Malformed("dependency-check", err)
	}

	return parseutil.Hardened(convert(budget, report))
}

// dcComponentDims builds the component identity dimensions for one
// Dependency-Check vulnerability: the purl when present, else the stable
// filename-derived package name fallback.
func dcComponentDims(purl, fileName string) []domain.Dimension {
	dims := []domain.Dimension{}
	if purl != "" {
		return append(dims, domain.Dimension{Key: domain.DimPURL, Value: purl})
	}
	if name := packageNameFromFile(fileName); name != "" {
		dims = append(dims, domain.Dimension{Key: domain.DimPackageName, Value: name})
	}
	return dims
}

// dcCVSSInfo builds the CVSS detail block when a vector is present.
func dcCVSSInfo(score float64, cvssVec, cvssVer string) *domain.CVSSInfo {
	if cvssVec == "" {
		return nil
	}
	return &domain.CVSSInfo{Version: cvssVer, Vector: cvssVec, Score: score}
}

// dcCVSSAll keeps both the v3 and the v2 vector of a vulnerability. The
// report's own "source" (for example NVD) is the scoring source when present.
func dcCVSSAll(v dcVulnerability) []domain.CVSSRecord {
	source := strings.ToLower(strings.TrimSpace(v.Source))
	var out []domain.CVSSRecord
	if v.CvssV3 != nil && v.CvssV3.BaseScore > 0 {
		if rec, ok := parseutil.NewCVSSRecord(v.CvssV3.VectorString, v.CvssV3.BaseScore, source); ok {
			out = parseutil.AddCVSS(out, rec)
		}
	}
	if v.CvssV2 != nil && v.CvssV2.Score > 0 {
		if rec, ok := parseutil.NewCVSSRecord(v.CvssV2.VectorString, v.CvssV2.Score, source); ok {
			out = parseutil.AddCVSS(out, rec)
		}
	}
	return out
}

func convertDCVulnerability(dep dcDependency, v dcVulnerability, purl string) domain.NormalizedFinding {
	severity := normalizeDCSeverity(v.Severity)
	score, cvssVec, cvssVer := extractCVSS(v)
	dims := append(
		[]domain.Dimension{{Key: domain.DimVulnerabilityID, Value: v.Name}},
		dcComponentDims(purl, dep.FileName)...,
	)
	filePath := parseutil.RepoPath(dep.FilePath)
	location := filePath
	if purl != "" {
		if _, name, version := domain.SplitPURL(purl); name != "" {
			location = domain.SCALocation(unescapePURL(name), unescapePURL(version), filePath)
		}
	}
	return domain.NormalizedFinding{
		Fingerprint: createFingerprint(v.Name, purl, filePath, parseutil.SanitizeText(dep.FileName, parseutil.MaxPathLength)),
		FindingKind: "sca",
		Title:       v.Name,
		Description: v.Description,
		Severity:    severity,
		Score:       score,
		Location:    location,
		CVSS:        dcCVSSInfo(score, cvssVec, cvssVer),
		CVSSAll:     dcCVSSAll(v),
		Dimensions:  dims,
		Extensions: map[string]any{
			"file_name": dep.FileName,
			"file_path": filePath,
			"cve":       v.Name,
			"severity":  v.Severity,
		},
	}
}

// appendDCPackages records the full package inventory of one dependency.
func appendDCPackages(budget *parseutil.Budget, nr *domain.NormalizedReport, dep dcDependency) error {
	filePath := parseutil.RepoPath(dep.FilePath)
	for _, p := range dep.Packages {
		purl := domain.NormalizePURL(p.ID)
		if purl == "" {
			continue
		}
		if err := budget.Add(1); err != nil {
			return err
		}
		pkgType, name, version := domain.SplitPURL(purl)
		nr.Packages = append(nr.Packages, parseutil.HardenPackage(domain.PackageRef{
			PURL:         purl,
			Ecosystem:    pkgType,
			Name:         name,
			Version:      version,
			ManifestPath: filePath,
		}))
	}
	return nil
}

func convert(budget *parseutil.Budget, report dcReport) (*domain.NormalizedReport, error) {
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: fingerprintVersion,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeFilesystem,
		Findings:           nil,
	}

	if len(report.Dependencies) > 0 {
		nr.Target = &domain.TargetInfo{
			Kind:       "filesystem",
			Identifier: parseutil.CleanFilePath(report.Dependencies[0].FilePath),
		}
	}

	for _, dep := range report.Dependencies {
		if err := appendDCPackages(budget, nr, dep); err != nil {
			return nil, err
		}

		purl := ""
		if len(dep.Packages) > 0 {
			purl = dep.Packages[0].ID
		}

		for _, v := range dep.Vulnerabilities {
			if err := budget.Add(1); err != nil {
				return nil, err
			}
			nr.Findings = append(nr.Findings, parseutil.HardenFinding(convertDCVulnerability(dep, v, purl)))
		}
	}

	return nr, nil
}

func extractCVSS(v dcVulnerability) (score float64, vector string, version string) {
	if v.CvssV3 != nil && v.CvssV3.BaseScore > 0 {
		score = v.CvssV3.BaseScore
		vector = v.CvssV3.VectorString
		version = "3.1"
		// The prefix decides: Dependency-Check also prints 3.0 vectors.
		if rec, ok := parseutil.NewCVSSRecord(vector, score, ""); ok {
			version = rec.Version
		}
		return
	}
	if v.CvssV2 != nil && v.CvssV2.Score > 0 {
		score = v.CvssV2.Score
		vector = v.CvssV2.VectorString
		version = "2.0"
		return
	}
	return 0, "", ""
}

// fingerprintVersion is the version of this scanner's identity formula.
// Version 2 keys a dependency without a purl on its file, so two such files
// with one CVE are two findings. Version 1 gave them all "CVE:".
const fingerprintVersion = 2

// createFingerprint is the vulnerability and the purl. A dependency with no
// purl (a .dll or .exe found by hash) has nothing but its file to name it, so
// the file's path stands in, then the file name. The path is repo-relative
// (parseutil.RepoPath): Dependency-Check writes it absolute, and the checkout
// directory changes from runner to runner.
func createFingerprint(vulnID, purl, filePath, fileName string) string {
	if purl != "" {
		return string(domain.SCAFingerprint(vulnID, purl))
	}
	if filePath != "" {
		return vulnID + ":" + filePath
	}
	return vulnID + ":" + fileName
}

func normalizeDCSeverity(s string) domain.Severity {
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

// packageNameFromFile derives a stable component name from a Dependency-Check
// report's fileName when the record carries no purl (e.g.
// "commons-lang3-3.12.0.jar" -> "commons-lang3"). It strips the file
// extension and, when the last dash-separated segment looks like a version,
// that segment too; the result is the component identity used for dedupe and
// waivers. Names with embedded digits (commons-lang3) are preserved.
func packageNameFromFile(fileName string) string {
	name := fileName
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	if i := strings.LastIndexByte(name, '-'); i > 0 {
		suffix := name[i+1:]
		if suffix != "" && suffix[0] >= '0' && suffix[0] <= '9' {
			name = name[:i]
		}
	}
	return name
}

// unescapePURL decodes the percent-escapes a package URL uses for reserved
// characters (the npm scope's "@" is written "%40"), so the display location
// reads like the package name. Text that is not valid escaping is kept as is.
func unescapePURL(s string) string {
	if decoded, err := url.PathUnescape(s); err == nil {
		return decoded
	}
	return s
}
