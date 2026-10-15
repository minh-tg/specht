package checkov

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
	"github.com/minh-tg/specht/internal/scanner"
)

type checkovReport struct {
	CheckType string         `json:"check_type"`
	Results   *checkovResult `json:"results"`
	Summary   checkovSummary `json:"summary"`
}

type checkovResult struct {
	PassedChecks  []json.RawMessage `json:"passed_checks"`
	FailedChecks  []checkovFinding  `json:"failed_checks"`
	SkippedChecks []json.RawMessage `json:"skipped_checks"`
	ParsingErrors []json.RawMessage `json:"parsing_errors"`
}

type checkovFinding struct {
	CheckID       string          `json:"check_id"`
	BcCheckID     string          `json:"bc_check_id"`
	CheckName     string          `json:"check_name"`
	CheckResult   checkovResult_  `json:"check_result"`
	FileLineRange []int           `json:"file_line_range"`
	FilePath      string          `json:"file_path"`
	Resource      string          `json:"resource"`
	CheckClass    string          `json:"check_class"`
	Guideline     string          `json:"guideline"`
	Severity      string          `json:"severity"`
	CodeBlock     json.RawMessage `json:"code_block"`
}

type checkovResult_ struct {
	Result string `json:"result"`
}

type checkovSummary struct {
	Passed         int    `json:"passed"`
	Failed         int    `json:"failed"`
	Skipped        int    `json:"skipped"`
	ParsingErrors  int    `json:"parsing_errors"`
	CheckovVersion string `json:"checkov_version"`
}

// Scanner adapts checkov JSON output to the normalized scanner model.
type Scanner struct{}

// NewScanner builds the checkov adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:                  "checkov",
		Version:               "3",
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          []scanner.FindingKind{"iac"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeIaC},
		ProvidesPackages:      false,
		SupportsAutoDetection: true,
	}
}

// SupportsIncremental declares checkov safe for incremental analysis
// IaC findings map to config files, so a changed-file scan
// covers what it claims to cover.
func (s *Scanner) SupportsIncremental() bool { return true }

func (s *Scanner) DetectFormat(data []byte) bool {
	return s.Recognize(data) == scanner.Definite
}

// Recognize grades a document. A Checkov report names its check type and has
// a results block, even when nothing failed, so it is definite or nothing.
func (s *Scanner) Recognize(data []byte) scanner.Recognition {
	shape, ok := parseutil.ReadShape(data)
	if !ok {
		return scanner.NotRecognized
	}
	if shape.IsObject() {
		if isFrameworkReport(shape) {
			return scanner.Definite
		}
		return scanner.NotRecognized
	}
	// Checkov writes an array with one report per framework when a directory
	// holds more than one kind of file. Every element has to be a report.
	if !shape.IsArray() || len(shape.Array) == 0 {
		return scanner.NotRecognized
	}
	for _, el := range shape.Array {
		sub, ok := parseutil.ReadShape(el)
		if !ok || !sub.IsObject() || !isFrameworkReport(sub) {
			return scanner.NotRecognized
		}
	}
	return scanner.Definite
}

// isFrameworkReport is true for one framework's report: it names its check
// type and has a results block, even when nothing failed.
func isFrameworkReport(shape parseutil.Shape) bool {
	return shape.String("check_type") != "" && shape.Has("results")
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	if s.Recognize(data) == scanner.NotRecognized {
		return nil, scanner.Unrecognized("checkov")
	}
	reports, err := decodeReports(data)
	if err != nil {
		return nil, scanner.Malformed("checkov", err)
	}
	return convertAll(reports), nil
}

// decodeReports reads either one framework's report (an object) or the array
// Checkov writes for several frameworks.
func decodeReports(data []byte) ([]checkovReport, error) {
	if shape, ok := parseutil.ReadShape(data); ok && shape.IsArray() {
		var reports []checkovReport
		if err := json.Unmarshal(data, &reports); err != nil {
			return nil, err
		}
		return reports, nil
	}
	var report checkovReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, err
	}
	return []checkovReport{report}, nil
}

// convertAll merges the framework reports of one run into one report. A single
// framework converts exactly as before. Several share one target kind, "iac",
// and the frameworks are listed on the scan scope. Files Checkov could not read
// are counted there too, because they are missing from the results.
func convertAll(reports []checkovReport) *domain.NormalizedReport {
	var nr *domain.NormalizedReport
	if len(reports) == 1 {
		nr = convert(reports[0])
	} else {
		nr = &domain.NormalizedReport{
			ContractVersion:    1,
			FingerprintVersion: 1,
			Completeness:       domain.CompletenessUnknown,
			ScanType:           domain.ScanTypeIaC,
			Target:             &domain.TargetInfo{Kind: "iac"},
		}
		seen := map[string]bool{}
		var frameworks []string
		for _, report := range reports {
			nr.Findings = append(nr.Findings, convert(report).Findings...)
			if !seen[report.CheckType] {
				seen[report.CheckType] = true
				frameworks = append(frameworks, report.CheckType)
			}
		}
		sort.Strings(frameworks)
		nr.ScanScope = &domain.ScanScope{Ext: map[string]string{"checkov_frameworks": strings.Join(frameworks, ",")}}
	}
	var parsingErrors int
	for _, report := range reports {
		parsingErrors += report.Summary.ParsingErrors
	}
	if parsingErrors > 0 {
		if nr.ScanScope == nil {
			nr.ScanScope = &domain.ScanScope{Ext: map[string]string{}}
		}
		nr.ScanScope.Ext["checkov_parsing_errors"] = strconv.Itoa(parsingErrors)
	}
	return nr
}

func convert(report checkovReport) *domain.NormalizedReport {
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeIaC,
		Findings:           nil,
	}

	nr.Target = &domain.TargetInfo{
		Kind: report.CheckType,
	}

	if report.Results == nil {
		return nr
	}

	for _, f := range report.Results.FailedChecks {
		nr.Findings = append(nr.Findings, parseutil.HardenFinding(convertCheck(f, report.CheckType)))
	}

	return nr
}

// convertCheck maps one failed checkov check to a normalized IaC finding.
func convertCheck(f checkovFinding, checkType string) domain.NormalizedFinding {
	file := parseutil.CleanFilePath(f.FilePath)
	if file == "" {
		file = "unknown"
	}

	dims := []domain.Dimension{
		{Key: "rule_id", Value: f.CheckID},
	}
	if f.Resource != "" {
		dims = append(dims, domain.Dimension{Key: "resource", Value: f.Resource})
	}
	ext := map[string]any{
		"file":        file,
		"check_class": f.CheckClass,
		"check_type":  checkType,
	}
	var aliases []string
	if f.BcCheckID != "" && f.BcCheckID != f.CheckID {
		aliases = append(aliases, f.BcCheckID)
		ext["bc_check_id"] = f.BcCheckID
	}
	if f.Guideline != "" {
		ext["guideline"] = f.Guideline
	}
	if len(f.CodeBlock) > 0 {
		ext["code_block"] = string(f.CodeBlock)
	}

	var fix *domain.FixInfo
	if f.Guideline != "" {
		fix = &domain.FixInfo{URL: f.Guideline}
	}

	codeLoc := checkCodeLocation(f, file)
	location := file
	if codeLoc != nil && codeLoc.StartLine > 0 {
		location = fmt.Sprintf("%s:%d", file, codeLoc.StartLine)
	}

	return domain.NormalizedFinding{
		Fingerprint:  "iac:" + f.CheckID + ":" + f.Resource + ":" + file,
		FindingKind:  "iac",
		Title:        f.CheckName,
		Description:  f.CheckName,
		Severity:     normalizeSeverity(f.Severity),
		Location:     location,
		Resource:     f.Resource,
		Aliases:      aliases,
		Fix:          fix,
		CodeLocation: codeLoc,
		Dimensions:   dims,
		Extensions:   ext,
	}
}

// checkCodeLocation maps the check's line range onto a code location.
func checkCodeLocation(f checkovFinding, file string) *domain.CodeLocation {
	switch len(f.FileLineRange) {
	case 0:
		return nil
	case 1:
		return &domain.CodeLocation{File: file, StartLine: parseutil.SafeLine(f.FileLineRange[0])}
	default:
		start := parseutil.SafeLine(f.FileLineRange[0])
		end := parseutil.SafeLine(f.FileLineRange[1])
		if end < start {
			end = start
		}
		return &domain.CodeLocation{
			File:      file,
			StartLine: start,
			EndLine:   end,
		}
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
