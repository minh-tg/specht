package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/scanner"
)

type trivyReport []trivyResult

type trivyResult struct {
	Target          string           `json:"Target"`
	Class           string           `json:"Class"`
	Type            string           `json:"Type"`
	Packages        []trivyPackage   `json:"Packages"`
	Vulnerabilities []trivyVuln      `json:"Vulnerabilities"`
	Secrets         []trivySecret    `json:"Secrets"`
	Misconfigs      []trivyMisconfig `json:"Misconfigurations"`
}

type trivyPackage struct {
	Name       string             `json:"Name"`
	Version    string             `json:"Version"`
	PkgID      string             `json:"PkgID"`
	Identifier trivyPkgIdentifier `json:"Identifier"`
}

type trivyVuln struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	PkgID            string               `json:"PkgID"`
	PkgName          string               `json:"PkgName"`
	PkgIdentifier    trivyPkgIdentifier   `json:"PkgIdentifier"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Status           string               `json:"Status"`
	Layer            *trivyLayer          `json:"Layer"`
	Severity         string               `json:"Severity"`
	Title            string               `json:"Title"`
	Description      string               `json:"Description"`
	PublishedDate    *string              `json:"PublishedDate"`
	LastModifiedDate *string              `json:"LastModifiedDate"`
	CweIDs           []string             `json:"CweIDs"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
	PrimaryURL       string               `json:"PrimaryURL"`
	DataSource       *trivyDataSource     `json:"DataSource"`
}

type trivyPkgIdentifier struct {
	PURL string `json:"PURL"`
	UID  string `json:"UID"`
}

type trivyLayer struct {
	DiffID string `json:"DiffID"`
}

type trivyCVSS struct {
	V4Score  float64 `json:"V4Score"`
	V4Vector string  `json:"V4Vector"`
	V3Score  float64 `json:"V3Score"`
	V3Vector string  `json:"V3Vector"`
	V2Score  float64 `json:"V2Score"`
	V2Vector string  `json:"V2Vector"`
}

type trivyDataSource struct {
	ID   string `json:"ID"`
	Name string `json:"Name"`
	URL  string `json:"URL"`
}

type trivySecret struct {
	RuleID   string          `json:"RuleID"`
	Category string          `json:"Category"`
	Severity string          `json:"Severity"`
	Title    string          `json:"Title"`
	Match    string          `json:"Match"`
	Code     json.RawMessage `json:"Code"`
	Layer    *trivyLayer     `json:"Layer"`
}

type trivyMisconfig struct {
	RuleID   string      `json:"RuleID"`
	Severity string      `json:"Severity"`
	Title    string      `json:"Title"`
	Message  string      `json:"Message"`
	Layer    *trivyLayer `json:"Layer"`
}

// Finding kind constants this adapter emits. Trivy emits multiple kinds from
// one report (sca, secret, iac), which is why capability discovery is
// per-descriptor rather than a single FindingKind() method.
const (
	kindSCA    = "sca"
	kindSecret = "secret"
	kindIaC    = "iac"
)

// Scanner adapts trivy JSON output to the normalized domain model.
type Scanner struct{}

// NewScanner builds the trivy adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:                  "trivy",
		Version:               "2",
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          []scanner.FindingKind{kindSCA, kindSecret, kindIaC},
		ScanTypes:             []domain.ScanType{domain.ScanTypeImage, domain.ScanTypeIaC, domain.ScanTypeFilesystem},
		ProvidesPackages:      true,
		SupportsAutoDetection: true,
	}
}

func (s *Scanner) DetectFormat(data []byte) bool {
	var probe []trivyResult
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	for _, r := range probe {
		if r.Target != "" {
			return true
		}
	}
	return false
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("trivy: parse json: %w", err)
	}

	return convert(report), nil
}

func convert(report trivyReport) *domain.NormalizedReport {
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeImage,
		Findings:           nil,
	}

	if len(report) > 0 {
		nr.Target = resultTarget(report[0])
	}

	for _, result := range report {
		// full package inventory, vulnerable or not
		addPackages(nr, result)
		addVulns(nr, result)
		addSecrets(nr, result)
		addMisconfigs(nr, result)
	}

	return nr
}

func resultTarget(first trivyResult) *domain.TargetInfo {
	target := &domain.TargetInfo{Identifier: first.Target}
	switch first.Class {
	case "os-pkgs", "lang-pkgs":
		target.Kind = "container_image"
	case "config":
		target.Kind = "iac"
	case "secret":
		target.Kind = "filesystem"
	default:
		target.Kind = "filesystem"
	}
	return target
}

func addPackages(nr *domain.NormalizedReport, result trivyResult) {
	for _, p := range result.Packages {
		purl := p.Identifier.PURL
		if purl == "" {
			purl = p.PkgID
		}
		if purl == "" {
			continue
		}
		nr.Packages = append(nr.Packages, domain.PackageRef{
			PURL:      domain.NormalizePURL(purl),
			Ecosystem: result.Type,
			Name:      p.Name,
			Version:   p.Version,
		})
	}
}

func addVulns(nr *domain.NormalizedReport, result trivyResult) {
	for _, v := range result.Vulnerabilities {
		purl := v.PkgIdentifier.PURL
		if purl == "" {
			purl = v.PkgID
		}

		dims := []domain.Dimension{
			{Key: domain.DimVulnerabilityID, Value: v.VulnerabilityID},
			{Key: domain.DimPackageName, Value: v.PkgName},
			{Key: domain.DimInstalledVer, Value: v.InstalledVersion},
			{Key: domain.DimPURL, Value: purl},
		}
		if v.FixedVersion != "" {
			dims = append(dims, domain.Dimension{Key: domain.DimFixedVersion, Value: v.FixedVersion})
		}

		ext := map[string]any{
			"target":       result.Target,
			"pkg_name":     v.PkgName,
			"pkg_id":       v.PkgID,
			"purl":         purl,
			"status":       v.Status,
			"severity_src": "trivy",
			"cwe_ids":      v.CweIDs,
		}
		if v.Layer != nil {
			ext["layer"] = v.Layer.DiffID
		}
		if v.PublishedDate != nil {
			ext["published"] = *v.PublishedDate
		}
		if v.LastModifiedDate != nil {
			ext["last_modified"] = *v.LastModifiedDate
		}
		if v.PrimaryURL != "" {
			ext["primary_url"] = v.PrimaryURL
		}
		if v.DataSource != nil {
			ext["data_source"] = v.DataSource.URL
		}

		nr.Findings = append(nr.Findings, domain.NormalizedFinding{
			Fingerprint: string(domain.SCAFingerprint(v.VulnerabilityID, purl)),
			FindingKind: kindSCA,
			Title:       v.Title,
			Description: v.Description,
			Severity:    normalizeSeverity(v.Severity),
			Score:       maxCVSSScore(v.CVSS),
			Location:    result.Target,
			Dimensions:  dims,
			Extensions:  ext,
		})
	}
}

// maxCVSSScore returns the highest available CVSS score for a vulnerability,
// preferring nvd, then redhat, then any vendor source, across CVSS versions.
func maxCVSSScore(cvss map[string]trivyCVSS) float64 {
	if cvss == nil {
		return 0
	}
	for _, source := range []string{"nvd", "redhat"} {
		if c, ok := cvss[source]; ok {
			if score := bestCVSSScore(c); score > 0 {
				return score
			}
		}
	}
	for _, c := range cvss {
		if score := bestCVSSScore(c); score > 0 {
			return score
		}
	}
	return 0
}

func bestCVSSScore(c trivyCVSS) float64 {
	switch {
	case c.V4Score > 0:
		return c.V4Score
	case c.V3Score > 0:
		return c.V3Score
	case c.V2Score > 0:
		return c.V2Score
	default:
		return 0
	}
}

func addSecrets(nr *domain.NormalizedReport, result trivyResult) {
	for _, s := range result.Secrets {
		fp := "secret:" + s.RuleID + ":" + result.Target
		nr.Findings = append(nr.Findings, domain.NormalizedFinding{
			Fingerprint: fp,
			FindingKind: kindSecret,
			Title:       s.Title,
			Severity:    normalizeSeverity(s.Severity),
			Location:    result.Target,
			Dimensions: []domain.Dimension{
				{Key: domain.DimRuleID, Value: s.RuleID},
			},
			Extensions: map[string]any{
				"category": s.Category,
			},
		})
	}
}

func addMisconfigs(nr *domain.NormalizedReport, result trivyResult) {
	for _, m := range result.Misconfigs {
		fp := "iac:" + m.RuleID + ":" + result.Target
		nr.Findings = append(nr.Findings, domain.NormalizedFinding{
			Fingerprint: fp,
			FindingKind: kindIaC,
			Title:       m.Title,
			Severity:    normalizeSeverity(m.Severity),
			Location:    result.Target,
			Dimensions: []domain.Dimension{
				{Key: domain.DimRuleID, Value: m.RuleID},
			},
			Extensions: map[string]any{
				"message":      m.Message,
				"severity_raw": m.Severity,
			},
		})
	}
}

func normalizeSeverity(s string) domain.Severity {
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
