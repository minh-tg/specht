package dependencycheck

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/scanner"
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
		Name:                  "dependency-check",
		Version:               "2",
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          []scanner.FindingKind{"sca"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeFilesystem},
		ProvidesPackages:      true,
		SupportsAutoDetection: true,
	}
}

func (s *Scanner) DetectFormat(data []byte) bool {
	var probe struct {
		ReportSchema string `json:"reportSchema"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.ReportSchema != ""
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	var report dcReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("dependency-check: parse json: %w", err)
	}

	return convert(report), nil
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

func convertDCVulnerability(dep dcDependency, v dcVulnerability, purl string) domain.NormalizedFinding {
	severity := normalizeDCSeverity(v.Severity)
	score, cvssVec, cvssVer := extractCVSS(v)
	dims := append(
		[]domain.Dimension{{Key: domain.DimVulnerabilityID, Value: v.Name}},
		dcComponentDims(purl, dep.FileName)...,
	)
	return domain.NormalizedFinding{
		Fingerprint: createFingerprint(v.Name, purl),
		FindingKind: "sca",
		Title:       v.Name,
		Description: v.Description,
		Severity:    severity,
		Score:       score,
		Location:    dep.FilePath,
		CVSS:        dcCVSSInfo(score, cvssVec, cvssVer),
		Dimensions:  dims,
		Extensions: map[string]any{
			"file_name": dep.FileName,
			"file_path": dep.FilePath,
			"cve":       v.Name,
			"severity":  v.Severity,
		},
	}
}

// appendDCPackages records the full package inventory of one dependency.
func appendDCPackages(nr *domain.NormalizedReport, dep dcDependency) {
	for _, p := range dep.Packages {
		purl := domain.NormalizePURL(p.ID)
		if purl == "" {
			continue
		}
		pkgType, name, version := domain.SplitPURL(purl)
		nr.Packages = append(nr.Packages, domain.PackageRef{
			PURL:         purl,
			Ecosystem:    pkgType,
			Name:         name,
			Version:      version,
			ManifestPath: dep.FilePath,
		})
	}
}

func convert(report dcReport) *domain.NormalizedReport {
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeFilesystem,
		Findings:           nil,
	}

	if len(report.Dependencies) > 0 {
		nr.Target = &domain.TargetInfo{
			Kind:       "filesystem",
			Identifier: report.Dependencies[0].FilePath,
		}
	}

	for _, dep := range report.Dependencies {
		appendDCPackages(nr, dep)

		purl := ""
		if len(dep.Packages) > 0 {
			purl = dep.Packages[0].ID
		}

		for _, v := range dep.Vulnerabilities {
			nr.Findings = append(nr.Findings, convertDCVulnerability(dep, v, purl))
		}
	}

	return nr
}

func extractCVSS(v dcVulnerability) (score float64, vector string, version string) {
	if v.CvssV3 != nil && v.CvssV3.BaseScore > 0 {
		score = v.CvssV3.BaseScore
		vector = v.CvssV3.VectorString
		version = "3.1"
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

func createFingerprint(vulnID, purl string) string {
	if purl != "" {
		return string(domain.SCAFingerprint(vulnID, purl))
	}
	return vulnID + ":"
}

func normalizeDCSeverity(s string) domain.Severity {
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
