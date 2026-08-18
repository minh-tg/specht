package dependencycheck

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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

type Scanner struct{}

func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "dependency-check" }

func (s *Scanner) FindingKind() string { return "sca" }

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
		ToolName:  "dependency-check",
		ScanType:  scanner.ScanTypeFilesystem,
		Findings:  nil,
		ScanScope: make(map[string]any),
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
				{Key: "vulnerability_id", Value: v.Name},
				{Key: "file_name", Value: dep.FileName},
			}
			if purl != "" {
				dims = append(dims, scanner.Dimension{Key: "purl", Value: purl})
			}

			var cvss *scanner.CVSSInfo
			if cvssVec != "" {
				cvss = &scanner.CVSSInfo{
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
				Display: map[string]any{
					"file_name": dep.FileName,
					"file_path": dep.FilePath,
				},
				Metadata: map[string]any{
					"cve":       v.Name,
					"severity":  v.Severity,
					"file_name": dep.FileName,
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

func normalizeDCSeverity(s string) scanner.Severity {
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
