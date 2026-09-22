// Package tfsec adapts tfsec JSON output to the normalized domain model.
// tfsec scans Terraform (and CloudFormation/Kubernetes/Dockerfile via its
// own loaders) for misconfigurations; only failed checks (status 1)
// become findings. Passed, unknown, and explicitly ignored results are
// skipped: they carry no remediation signal.
package tfsec

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/scanner"
)

const unknownFile = "(unknown)"

// Scanner adapts tfsec JSON output to the normalized domain model.
type Scanner struct{}

// NewScanner builds the tfsec adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:                  "tfsec",
		Version:               "1",
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          []scanner.FindingKind{"iac"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeIaC},
		ProvidesPackages:      false,
		SupportsAutoDetection: true,
	}
}

// SupportsIncremental declares tfsec safe for incremental analysis
// (SOLO-165): IaC findings map to config files, so a changed-file scan
// covers what it claims to cover.
func (s *Scanner) SupportsIncremental() bool { return true }

func (s *Scanner) DetectFormat(data []byte) bool {
	var probe struct {
		Results    []tfsecResult `json:"results"`
		Statistics *struct{}     `json:"statistics"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.Statistics != nil && probe.Results != nil
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	var report tfsecReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("tfsec: parse json: %w", err)
	}
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeIaC,
		Target:             &domain.TargetInfo{Kind: "terraform"},
	}
	for _, r := range report.Results {
		if r.Status != 1 || r.RuleID == "" {
			continue
		}
		nr.Findings = append(nr.Findings, convert(r))
	}
	return nr, nil
}

type tfsecReport struct {
	Results []tfsecResult `json:"results"`
}

type tfsecResult struct {
	RuleID          string `json:"rule_id"`
	LongID          string `json:"long_id"`
	RuleDescription string `json:"rule_description"`
	Description     string `json:"description"`
	Impact          string `json:"impact"`
	Resolution      string `json:"resolution"`
	Severity        string `json:"severity"`
	Status          int    `json:"status"`
	Resource        string `json:"resource"`
	Location        struct {
		Filename  string `json:"filename"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
	} `json:"location"`
	Links []string `json:"links"`
}

// tfsecFileLocation resolves the display file and location strings.
func tfsecFileLocation(r tfsecResult) (string, string) {
	file := r.Location.Filename
	if file == "" {
		file = unknownFile
	}
	location := file
	if r.Location.StartLine > 0 {
		location = file + ":" + strconv.Itoa(r.Location.StartLine)
	}
	return file, location
}

// tfsecDescriptionText builds the description from the check text, rule
// description fallback, and impact note.
func tfsecDescriptionText(r tfsecResult) string {
	description := r.Description
	if description == "" {
		description = r.RuleDescription
	}
	if r.Impact != "" {
		description += " Impact: " + r.Impact
	}
	return description
}

// tfsecDimensions builds the rule/resource/file/line dimensions.
func tfsecDimensions(r tfsecResult, file string) []domain.Dimension {
	dims := []domain.Dimension{{Key: domain.DimRuleID, Value: r.RuleID}}
	if r.Resource != "" {
		dims = append(dims, domain.Dimension{Key: domain.DimResource, Value: r.Resource})
	}
	if file == unknownFile {
		return dims
	}
	dims = append(dims, domain.Dimension{Key: domain.DimFile, Value: file})
	if r.Location.StartLine > 0 {
		dims = append(dims, domain.Dimension{Key: domain.DimLine, Value: strconv.Itoa(r.Location.StartLine)})
	}
	return dims
}

// tfsecFixInfo builds the fix guidance from resolution text and links.
func tfsecFixInfo(r tfsecResult) *domain.FixInfo {
	if r.Resolution == "" && len(r.Links) == 0 {
		return nil
	}
	fix := &domain.FixInfo{Summary: r.Resolution}
	if len(r.Links) > 0 {
		fix.URL = r.Links[0]
	}
	return fix
}

func convert(r tfsecResult) domain.NormalizedFinding {
	file, location := tfsecFileLocation(r)
	description := tfsecDescriptionText(r)
	dims := tfsecDimensions(r, file)
	meta := map[string]any{}
	if r.LongID != "" && r.LongID != r.RuleID {
		meta["long_id"] = r.LongID
	}
	fix := tfsecFixInfo(r)
	title := r.RuleDescription
	if title == "" {
		title = r.RuleID
	}
	f := domain.NormalizedFinding{
		Fingerprint: "iac:" + r.RuleID + ":" + r.Resource,
		FindingKind: "iac",
		Title:       title,
		Description: description,
		Severity:    normalizeSeverity(r.Severity),
		Location:    location,
		Resource:    r.Resource,
		Fix:         fix,
		Dimensions:  dims,
		Extensions:  meta,
	}
	if file != unknownFile {
		f.CodeLocation = &domain.CodeLocation{
			File:      file,
			StartLine: r.Location.StartLine,
			EndLine:   r.Location.EndLine,
		}
	}
	return f
}

func normalizeSeverity(s string) domain.Severity {
	switch strings.ToUpper(s) {
	case "CRITICAL":
		return domain.SeverityCritical
	case "HIGH", "ERROR":
		return domain.SeverityHigh
	case "MEDIUM", "WARNING":
		return domain.SeverityMedium
	case "LOW":
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}
