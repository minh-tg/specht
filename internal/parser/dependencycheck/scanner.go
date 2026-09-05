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
		ScanTypes:             []scanner.ScanType{scanner.ScanTypeFilesystem},
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

func (s *Scanner) Parse(ctx context.Context, data []byte) (*scanner.NormalizedReport, error) {
	var report dcReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("dependency-check: parse json: %w", err)
	}

	return convert(report), nil
}

func convert(report dcReport) *scanner.NormalizedReport {
	nr := &scanner.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           scanner.ScanTypeFilesystem,
		Findings:           nil,
	}

	if len(report.Dependencies) > 0 {
		nr.Target = &scanner.TargetInfo{
			Kind:       "filesystem",
			Identifier: report.Dependencies[0].FilePath,
		}
	}

	for _, dep := range report.Dependencies {
		// full package inventory, vulnerable or not
		for _, p := range dep.Packages {
			purl := scanner.NormalizePURL(p.ID)
			if purl == "" {
				continue
			}
			pkgType, name, version := scanner.SplitPURL(purl)
			nr.Packages = append(nr.Packages, scanner.PackageRef{
				PURL:         purl,
				Ecosystem:    pkgType,
				Name:         name,
				Version:      version,
				ManifestPath: dep.FilePath,
			})
		}

		purl := ""
		if len(dep.Packages) > 0 {
			purl = dep.Packages[0].ID
		}

		for _, v := range dep.Vulnerabilities {
			severity := normalizeDCSeverity(v.Severity)
			score, cvssVec, cvssVer := extractCVSS(v)

			fingerprint := createFingerprint(v.Name, purl)

			dims := []scanner.Dimension{
				{Key: domain.DimVulnerabilityID, Value: v.Name},
			}
			if purl != "" {
				dims = append(dims, scanner.Dimension{Key: domain.DimPURL, Value: purl})
			} else if name := packageNameFromFile(dep.FileName); name != "" {
				// Stable fallback component identity for Dependency-Check
				// records without a purl: waivers and dedupe need a stable
				// component key even when the report omits purls.
				dims = append(dims, scanner.Dimension{Key: domain.DimPackageName, Value: name})
			}

			var cvss *domain.CVSSInfo
			if cvssVec != "" {
				cvss = &domain.CVSSInfo{
					Version: cvssVer,
					Vector:  cvssVec,
					Score:   score,
				}
			}

			nr.Findings = append(nr.Findings, scanner.NormalizedFinding{
				Fingerprint: fingerprint,
				FindingKind: "sca",
				Title:       v.Name,
				Description: v.Description,
				Severity:    severity,
				Score:       score,
				Location:    dep.FilePath,
				CVSS:        cvss,
				Dimensions:  dims,
				Extensions: map[string]any{
					"file_name": dep.FileName,
					"file_path": dep.FilePath,
					"cve":       v.Name,
					"severity":  v.Severity,
				},
			})
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
		return string(scanner.SCAFingerprint(vulnID, purl))
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
