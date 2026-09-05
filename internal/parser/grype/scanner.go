package grype

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/scanner"
)

type grypeDoc struct {
	Matches []grypeMatch `json:"matches"`
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
		Name:                  "grype",
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
	var probe struct {
		Matches []json.RawMessage `json:"matches"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return len(probe.Matches) > 0
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	var doc grypeDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("grype: parse json: %w", err)
	}

	return convert(doc), nil
}

func convert(doc grypeDoc) *domain.NormalizedReport {
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeFilesystem,
		Findings:           nil,
	}

	if len(doc.Matches) > 0 && len(doc.Matches[0].Artifact.Locations) > 0 {
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
	seen := make(map[string]struct{})
	for _, match := range doc.Matches {
		artifact := match.Artifact
		purl := domain.NormalizePURL(artifact.PURL)
		if purl == "" {
			continue
		}
		if _, ok := seen[purl]; ok {
			continue
		}
		seen[purl] = struct{}{}

		manifestPath := ""
		if len(artifact.Locations) > 0 {
			manifestPath = artifact.Locations[0].Path
		}
		pkgType, _, _ := domain.SplitPURL(purl)

		nr.Packages = append(nr.Packages, domain.PackageRef{
			PURL:         purl,
			Ecosystem:    pkgType,
			Name:         artifact.Name,
			Version:      artifact.Version,
			ManifestPath: manifestPath,
		})
	}

	for _, match := range doc.Matches {
		vuln := match.Vulnerability
		artifact := match.Artifact

		purl := artifact.PURL
		fingerprint := string(domain.SCAFingerprint(vuln.ID, purl))

		severity := normalizeGrypeSeverity(vuln.Severity)

		score, cvssVec, cvssVer := pickCVSS(vuln.CVSS)
		aliases := extractAliases(match.RelatedVulnerabilities)

		// If no CVSS on primary, check relatedVulnerabilities
		if score == 0 {
			for _, rv := range match.RelatedVulnerabilities {
				if len(rv.CVSS) > 0 {
					s, vec, ver := pickCVSS(rv.CVSS)
					if s > 0 {
						score = s
						cvssVec = vec
						cvssVer = ver
						break
					}
				}
			}
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
			summary := strings.Join(vuln.Fix.Versions, ", ")
			fix = &domain.FixInfo{Summary: summary}
		}

		dims := []domain.Dimension{
			{Key: "vulnerability_id", Value: vuln.ID},
			{Key: "package_name", Value: artifact.Name},
			{Key: "installed_version", Value: artifact.Version},
			{Key: "purl", Value: purl},
		}
		if fix != nil {
			dims = append(dims, domain.Dimension{Key: "fixed_version", Value: fix.Summary})
		}

		location := ""
		if len(artifact.Locations) > 0 {
			location = artifact.Locations[0].Path
		}

		nr.Findings = append(nr.Findings, domain.NormalizedFinding{
			Fingerprint: fingerprint,
			FindingKind: "sca",
			Title:       vuln.ID + " in " + artifact.Name,
			Description: vuln.Description,
			Severity:    severity,
			Score:       score,
			Location:    location,
			Resource:    artifact.Name + "@" + artifact.Version,
			Aliases:     aliases,
			CVSS:        cvss,
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
		})
	}

	return nr
}

func pickCVSS(cvssList []grypeCVSS) (score float64, vector string, version string) {
	for _, c := range cvssList {
		if c.Metrics.BaseScore > 0 {
			return c.Metrics.BaseScore, c.Vector, c.Version
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
