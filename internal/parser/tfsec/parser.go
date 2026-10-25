// Package tfsec adapts tfsec JSON output to the normalized domain model.
// tfsec scans Terraform (and CloudFormation/Kubernetes/Dockerfile via its
// own loaders) for misconfigurations; only failed checks (status 0)
// become findings. Passed, unknown, and explicitly ignored results are
// skipped: they carry no remediation signal.
package tfsec

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
	"github.com/minh-tg/specht/internal/scanner"
)

const unknownFile = "(unknown)"

// Scanner adapts tfsec JSON output to the normalized domain model.
type Scanner struct{}

// NewScanner builds the tfsec adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:        "tfsec",
		DisplayName: "tfsec",
		Formats: []scanner.Format{
			{
				Name:       "JSON",
				Extensions: []string{".json"},
				Command:    `tfsec . --format json --out tfsec.json`,
				TestedWith: "tfsec 1.28.14",
			},
		},
		Version:               "1",
		ContractVersion:       1,
		FingerprintVersion:    fingerprintVersion,
		FindingKinds:          []scanner.FindingKind{"iac"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeIaC},
		ProvidesPackages:      false,
		SupportsAutoDetection: true,
	}
}

// SupportsIncremental declares tfsec safe for incremental analysis
// IaC findings map to config files, so a changed-file scan
// covers what it claims to cover.
func (s *Scanner) SupportsIncremental() bool { return true }

func (s *Scanner) DetectFormat(data []byte) bool {
	return s.Recognize(data) == scanner.Definite
}

// Recognize grades a document. A tfsec result carries a rule id and a long
// id. A report with no results is only possible, because other tools write
// an empty results list too.
func (s *Scanner) Recognize(data []byte) scanner.Recognition {
	shape, ok := parseutil.ReadShape(data)
	if !ok || !shape.IsObject() {
		return scanner.NotRecognized
	}
	results, present := shape.List("results")
	if !present {
		return scanner.NotRecognized
	}
	if shape.Has("statistics") {
		return scanner.Definite
	}
	for _, r := range results {
		if parseutil.ObjectHas(r, "rule_id", "long_id") {
			return scanner.Definite
		}
	}
	if len(results) == 0 {
		return scanner.Possible
	}
	return scanner.NotRecognized
}

// findingArrays names the arrays of a document that carry findings and
// packages (see scanner.CheckDocument).
var findingArrays = []string{"results"}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	budget, err := parseutil.NewBudget(ctx, data, findingArrays...)
	if err != nil {
		return nil, err
	}
	if s.Recognize(data) == scanner.NotRecognized {
		return nil, scanner.Unrecognized("tfsec")
	}
	var report tfsecReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, scanner.Malformed("tfsec", err)
	}
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: fingerprintVersion,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeIaC,
		Target:             &domain.TargetInfo{Kind: "terraform"},
	}
	for _, r := range report.Results {
		if r.Status == nil || *r.Status != 0 || r.RuleID == "" {
			continue
		}
		if err := budget.Add(1); err != nil {
			return nil, err
		}
		nr.Findings = append(nr.Findings, parseutil.HardenFinding(convert(r)))
	}
	return parseutil.HardenReport(nr), nil
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
	Status          *int   `json:"status"`
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
	file := parseutil.CleanFilePath(r.Location.Filename)
	if file == "" {
		file = unknownFile
	}
	location := file
	startLine := parseutil.SafeLine(r.Location.StartLine)
	if startLine > 0 {
		location = file + ":" + strconv.Itoa(startLine)
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
		Fingerprint: fingerprint(r, file),
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
		start := parseutil.SafeLine(r.Location.StartLine)
		end := parseutil.SafeLine(r.Location.EndLine)
		if end < start {
			end = start
		}
		f.CodeLocation = &domain.CodeLocation{
			File:      file,
			StartLine: start,
			EndLine:   end,
		}
	}
	return f
}

// fingerprintVersion is the version of this scanner's identity formula.
// Version 2 adds the file, so one resource address in two modules is two
// findings. Version 1 was the rule and the resource only.
const fingerprintVersion = 2

// fingerprint is the rule, the resource and the file, the IaC identity
// Checkov findings use, so a finding stays put when its resource moves
// within the file. A result that names no resource falls back to the line.
func fingerprint(r tfsecResult, file string) string {
	fp := "iac:" + r.RuleID + ":" + r.Resource + ":" + file
	if line := parseutil.SafeLine(r.Location.StartLine); r.Resource == "" && line > 0 {
		fp += ":" + strconv.Itoa(line)
	}
	return fp
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
