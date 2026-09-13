package checkov

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/xMinhx/specht/internal/domain"
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
// (SOLO-165): IaC findings map to config files, so a changed-file scan
// covers what it claims to cover.
func (s *Scanner) SupportsIncremental() bool { return true }

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

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	var report checkovReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("checkov: parse json: %w", err)
	}

	return convert(report), nil
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
		file := f.FilePath
		if file == "" {
			file = "unknown"
		}

		fingerprint := "iac:" + f.CheckID + ":" + f.Resource + ":" + file

		severity := normalizeSeverity(f.Severity)

		dims := []domain.Dimension{
			{Key: "rule_id", Value: f.CheckID},
		}
		if f.Resource != "" {
			dims = append(dims, domain.Dimension{Key: "resource", Value: f.Resource})
		}
		ext := map[string]any{
			"file":        file,
			"check_class": f.CheckClass,
			"check_type":  report.CheckType,
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

		var codeLoc *domain.CodeLocation
		if len(f.FileLineRange) >= 2 {
			codeLoc = &domain.CodeLocation{
				File:      file,
				StartLine: f.FileLineRange[0],
				EndLine:   f.FileLineRange[1],
			}
		} else if len(f.FileLineRange) == 1 {
			codeLoc = &domain.CodeLocation{
				File:      file,
				StartLine: f.FileLineRange[0],
			}
		}

		location := file
		if codeLoc != nil && codeLoc.StartLine > 0 {
			location = fmt.Sprintf("%s:%d", file, codeLoc.StartLine)
		}

		nr.Findings = append(nr.Findings, domain.NormalizedFinding{
			Fingerprint:  fingerprint,
			FindingKind:  "iac",
			Title:        f.CheckName,
			Description:  f.CheckName,
			Severity:     severity,
			Location:     location,
			Resource:     f.Resource,
			Aliases:      aliases,
			Fix:          fix,
			CodeLocation: codeLoc,
			Dimensions:   dims,
			Extensions:   ext,
		})
	}

	return nr
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
