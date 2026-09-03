package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

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

// Scanner adapts trivy JSON output to the normalized scanner model.
type Scanner struct{}

// NewScanner builds the trivy adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "trivy" }

func (s *Scanner) FindingKind() string { return "sca" }

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

func (s *Scanner) Parse(ctx context.Context, data []byte) (*scanner.NormalizedReport, error) {
	var report trivyReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("trivy: parse json: %w", err)
	}

	return convert(report), nil
}

func convert(report trivyReport) *scanner.NormalizedReport {
	nr := &scanner.NormalizedReport{
		ToolName:  "trivy",
		ScanType:  scanner.ScanTypeImage,
		Findings:  nil,
		ScanScope: make(map[string]any),
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

func resultTarget(first trivyResult) *scanner.TargetInfo {
	target := &scanner.TargetInfo{Identifier: first.Target}
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

func addPackages(nr *scanner.NormalizedReport, result trivyResult) {
	for _, p := range result.Packages {
		purl := p.Identifier.PURL
		if purl == "" {
			purl = p.PkgID
		}
		if purl == "" {
			continue
		}
		nr.Packages = append(nr.Packages, scanner.PackageRef{
			PURL:      scanner.NormalizePURL(purl),
			Ecosystem: result.Type,
			Name:      p.Name,
			Version:   p.Version,
		})
	}
}

func addVulns(nr *scanner.NormalizedReport, result trivyResult) {
	for _, v := range result.Vulnerabilities {
		purl := v.PkgIdentifier.PURL
		if purl == "" {
			purl = v.PkgID
		}

		dims := []scanner.Dimension{
			{Key: "vulnerability_id", Value: v.VulnerabilityID},
			{Key: "package_name", Value: v.PkgName},
			{Key: "installed_version", Value: v.InstalledVersion},
			{Key: "purl", Value: purl},
		}
		if v.FixedVersion != "" {
			dims = append(dims, scanner.Dimension{Key: "fixed_version", Value: v.FixedVersion})
		}

		display := map[string]any{
			"target":   result.Target,
			"pkg_name": v.PkgName,
			"status":   v.Status,
		}
		if v.Layer != nil {
			display["layer"] = v.Layer.DiffID
		}

		meta := map[string]any{
			"pkg_id":       v.PkgID,
			"purl":         purl,
			"severity_src": "trivy",
			"cwe_ids":      v.CweIDs,
			"status":       v.Status,
		}
		if v.PublishedDate != nil {
			meta["published"] = *v.PublishedDate
		}
		if v.LastModifiedDate != nil {
			meta["last_modified"] = *v.LastModifiedDate
		}
		if v.PrimaryURL != "" {
			meta["primary_url"] = v.PrimaryURL
		}
		if v.DataSource != nil {
			meta["data_source"] = v.DataSource.URL
		}

		nr.Findings = append(nr.Findings, scanner.NormalizedFinding{
			Fingerprint: string(scanner.SCAFingerprint(v.VulnerabilityID, purl)),
			FindingKind: "sca",
			Title:       v.Title,
			Description: v.Description,
			Severity:    normalizeSeverity(v.Severity),
			Score:       maxCVSSScore(v.CVSS),
			Location:    result.Target,
			Dimensions:  dims,
			Display:     display,
			Metadata:    meta,
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

func addSecrets(nr *scanner.NormalizedReport, result trivyResult) {
	for _, s := range result.Secrets {
		fp := "secret:" + s.RuleID + ":" + result.Target
		nr.Findings = append(nr.Findings, scanner.NormalizedFinding{
			Fingerprint: fp,
			FindingKind: "secret",
			Title:       s.Title,
			Severity:    normalizeSeverity(s.Severity),
			Dimensions: []scanner.Dimension{
				{Key: "rule_id", Value: s.RuleID},
				{Key: "category", Value: s.Category},
			},
			Display: map[string]any{
				"target":   result.Target,
				"category": s.Category,
			},
			Metadata: map[string]any{
				"category": s.Category,
				"rule_id":  s.RuleID,
			},
		})
	}
}

func addMisconfigs(nr *scanner.NormalizedReport, result trivyResult) {
	for _, m := range result.Misconfigs {
		fp := "iac:" + m.RuleID + ":" + result.Target
		nr.Findings = append(nr.Findings, scanner.NormalizedFinding{
			Fingerprint: fp,
			FindingKind: "iac",
			Title:       m.Title,
			Severity:    normalizeSeverity(m.Severity),
			Dimensions: []scanner.Dimension{
				{Key: "rule_id", Value: m.RuleID},
			},
			Display: map[string]any{
				"target":  result.Target,
				"message": m.Message,
			},
			Metadata: map[string]any{
				"rule_id":  m.RuleID,
				"severity": m.Severity,
				"message":  m.Message,
			},
		})
	}
}

func normalizeSeverity(s string) scanner.Severity {
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
