package checkov

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xMinhx/specht/internal/scanner"
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

type Scanner struct{}

func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Name() string { return "checkov" }

func (s *Scanner) FindingKind() string { return "iac" }

func (s *Scanner) DetectFormat(data []byte) bool {
	var probe struct {
		CheckType string          `json:"check_type"`
		Results   json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return probe.CheckType != "" && probe.Results != nil
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*scanner.NormalizedReport, error) {
	var report checkovReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("checkov: parse json: %w", err)
	}

	return convert(report), nil
}

func convert(report checkovReport) *scanner.NormalizedReport {
	nr := &scanner.NormalizedReport{
		ToolName:  "checkov",
		ScanType:  scanner.ScanTypeIaC,
		Findings:  nil,
		ScanScope: make(map[string]any),
	}

	nr.ToolVersion = report.Summary.CheckovVersion

	nr.Target = &scanner.TargetInfo{
		Kind: report.CheckType,
	}

	if report.Results == nil {
		return nr
	}

	for _, f := range report.Results.FailedChecks {
		file := f.FilePath
		if file == "" {
			file = "unknown"
		}

		fingerprint := "iac:" + f.CheckID + ":" + f.Resource + ":" + file

		severity := normalizeSeverity(f.Severity)

		dims := []scanner.Dimension{
			{Key: "rule_id", Value: f.CheckID},
		}
		if f.Resource != "" {
			dims = append(dims, scanner.Dimension{Key: "resource", Value: f.Resource})
		}

		display := map[string]any{
			"file":     file,
			"resource": f.Resource,
		}
		if f.Guideline != "" {
			display["guideline"] = f.Guideline
		}

		meta := map[string]any{
			"check_class": f.CheckClass,
			"check_type":  report.CheckType,
		}
		if f.Guideline != "" {
			meta["guideline"] = f.Guideline
		}
		if len(f.CodeBlock) > 0 {
			meta["code_block"] = string(f.CodeBlock)
		}

		var fix *scanner.FixInfo
		if f.Guideline != "" {
			fix = &scanner.FixInfo{URL: f.Guideline}
		}

		var codeLoc *scanner.CodeLocation
		if len(f.FileLineRange) >= 2 {
			codeLoc = &scanner.CodeLocation{
				File:      file,
				StartLine: f.FileLineRange[0],
				EndLine:   f.FileLineRange[1],
			}
		} else if len(f.FileLineRange) == 1 {
			codeLoc = &scanner.CodeLocation{
				File:      file,
				StartLine: f.FileLineRange[0],
			}
		}

		location := file
		if codeLoc != nil && codeLoc.StartLine > 0 {
			location = fmt.Sprintf("%s:%d", file, codeLoc.StartLine)
		}

		nr.Findings = append(nr.Findings, scanner.NormalizedFinding{
			Fingerprint:  fingerprint,
			FindingKind:  "iac",
			Title:        f.CheckName,
			Description:  f.CheckName,
			Severity:     severity,
			Location:     location,
			Resource:     f.Resource,
			Fix:          fix,
			CodeLocation: codeLoc,
			Dimensions:   dims,
			Display:      display,
			Metadata:     meta,
		})
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
