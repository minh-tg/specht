package trivy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/vulnserve/vulnserve/internal/scanner"
)

type trivyReport []trivyResult

type trivyResult struct {
	Target          string             `json:"Target"`
	Class           string             `json:"Class"`
	Type            string             `json:"Type"`
	Vulnerabilities []trivyVuln        `json:"Vulnerabilities"`
	Secrets         []trivySecret      `json:"Secrets"`
	Misconfigs      []trivyMisconfig   `json:"Misconfigurations"`
}

type trivyVuln struct {
	VulnerabilityID  string              `json:"VulnerabilityID"`
	PkgID            string              `json:"PkgID"`
	PkgName          string              `json:"PkgName"`
	PkgIdentifier    trivyPkgIdentifier  `json:"PkgIdentifier"`
	InstalledVersion string              `json:"InstalledVersion"`
	FixedVersion     string              `json:"FixedVersion"`
	Status           string              `json:"Status"`
	Layer            *trivyLayer         `json:"Layer"`
	Severity         string              `json:"Severity"`
	Title            string              `json:"Title"`
	Description      string              `json:"Description"`
	PublishedDate    *string             `json:"PublishedDate"`
	LastModifiedDate *string             `json:"LastModifiedDate"`
	CweIDs           []string            `json:"CweIDs"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
	PrimaryURL       string              `json:"PrimaryURL"`
	DataSource       *trivyDataSource    `json:"DataSource"`
}

type trivyPkgIdentifier struct {
	PURL string `json:"PURL"`
	UID  string `json:"UID"`
}

type trivyLayer struct {
	DiffID string `json:"DiffID"`
}

type trivyCVSS struct {
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
	RuleID    string   `json:"RuleID"`
	Category  string   `json:"Category"`
	Severity  string   `json:"Severity"`
	Title     string   `json:"Title"`
	Match     string   `json:"Match"`
	Code      json.RawMessage `json:"Code"`
	Layer     *trivyLayer     `json:"Layer"`
}

type trivyMisconfig struct {
	RuleID    string   `json:"RuleID"`
	Severity  string   `json:"Severity"`
	Title     string   `json:"Title"`
	Message   string   `json:"Message"`
	Layer     *trivyLayer     `json:"Layer"`
}

type Parser struct{}

func NewParser() *Parser { return &Parser{} }

func (p *Parser) Name() string { return "trivy" }

func (p *Parser) ScanTypes() []scanner.ScanType {
	return []scanner.ScanType{scanner.ScanTypeImage, scanner.ScanTypeFilesystem, scanner.ScanTypeRepository, scanner.ScanTypeIaC}
}

func (p *Parser) Detect(data []byte) bool {
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

func (p *Parser) Parse(ctx context.Context, r io.Reader) (*scanner.NormalizedReport, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("trivy: read input: %w", err)
	}

	var report trivyReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("trivy: parse json: %w", err)
	}

	return convert(report), nil
}

func convert(report trivyReport) *scanner.NormalizedReport {
	nr := &scanner.NormalizedReport{
		ScannerName: "trivy",
		ScanType:    scanner.ScanTypeImage,
		Findings:    nil,
		ScanScope:   make(map[string]any),
	}

	if len(report) > 0 {
		first := report[0]
		target := &scanner.TargetInfo{
			Identifier: first.Target,
		}
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
		nr.Target = target
	}

	for _, result := range report {
		// vulnerabilities
		for _, v := range result.Vulnerabilities {
			severity := normalizeSeverity(v.Severity)
			var score float64
			if cvss, ok := v.CVSS["nvd"]; ok && cvss.V3Score > 0 {
				score = cvss.V3Score
			} else if cvss, ok := v.CVSS["redhat"]; ok && cvss.V3Score > 0 {
				score = cvss.V3Score
			} else {
				for _, c := range v.CVSS {
					if c.V3Score > 0 {
						score = c.V3Score
						break
					} else if c.V2Score > 0 {
						score = c.V2Score
					}
				}
			}

			purl := v.PkgIdentifier.PURL
			if purl == "" {
				purl = v.PkgID
			}

			fingerprint := string(scanner.SCAFingerprint(v.VulnerabilityID, purl))

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
				"purl":        purl,
				"severity_src": "trivy",
				"cwe_ids":     v.CweIDs,
				"status":      v.Status,
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
				Fingerprint: fingerprint,
				FindingKind: "sca_vulnerability",
				Title:       v.Title,
				Description: v.Description,
				Severity:    severity,
				Score:       score,
				Location:    result.Target,
				Dimensions:  dims,
				Display:     display,
				Metadata:    meta,
			})
		}

		// secrets
		for _, s := range result.Secrets {
			severity := normalizeSeverity(s.Severity)
			fp := "secret:" + s.RuleID + ":" + result.Target
			nr.Findings = append(nr.Findings, scanner.NormalizedFinding{
				Fingerprint: fp,
				FindingKind: "secret",
				Title:       s.Title,
				Severity:    severity,
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

		// misconfigurations
		for _, m := range result.Misconfigs {
			severity := normalizeSeverity(m.Severity)
			fp := "iac:" + m.RuleID + ":" + result.Target
			nr.Findings = append(nr.Findings, scanner.NormalizedFinding{
				Fingerprint: fp,
				FindingKind: "iac",
				Title:       m.Title,
				Severity:    severity,
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

	return nr
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
