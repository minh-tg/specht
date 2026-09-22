package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/scanner"
)

type sarifReport struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool      sarifTool       `json:"tool"`
	Results   []sarifResult   `json:"results"`
	Artifacts []sarifArtifact `json:"artifacts"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name            string      `json:"name"`
	Version         string      `json:"version"`
	SemanticVersion string      `json:"semanticVersion"`
	Rules           []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string           `json:"id"`
	ShortDescription     sarifDescription `json:"shortDescription"`
	FullDescription      sarifDescription `json:"fullDescription"`
	DefaultConfiguration sarifConfig      `json:"defaultConfiguration"`
	Properties           map[string]any   `json:"properties"`
}

type sarifDescription struct {
	Text string `json:"text"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifResult struct {
	RuleID       string            `json:"ruleId"`
	RuleIndex    int               `json:"ruleIndex"`
	Level        string            `json:"level"`
	Message      sarifMessage      `json:"message"`
	Locations    []sarifLocation   `json:"locations"`
	Fingerprints map[string]string `json:"fingerprints"`
	Properties   map[string]any    `json:"properties"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int           `json:"startLine"`
	EndLine     int           `json:"endLine"`
	StartColumn int           `json:"startColumn"`
	EndColumn   int           `json:"endColumn"`
	Snippet     *sarifSnippet `json:"snippet"`
}

type sarifSnippet struct {
	Text string `json:"text"`
}

type sarifArtifact struct {
	Location sarifArtifactLocation `json:"location"`
}

// Scanner adapts semgrep SARIF output to the normalized scanner model.
type Scanner struct{}

// NewScanner builds the semgrep adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:                  "semgrep",
		Version:               "2.1",
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          []scanner.FindingKind{"sast"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeFilesystem, domain.ScanTypeRepository},
		ProvidesPackages:      false,
		SupportsAutoDetection: true,
	}
}

// SupportsIncremental declares semgrep safe for incremental analysis
// (SOLO-165): SAST findings map to source files, so a changed-file scan
// covers what it claims to cover.
func (s *Scanner) SupportsIncremental() bool { return true }

func (s *Scanner) DetectFormat(data []byte) bool {
	var probe sarifReport
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	if len(probe.Runs) == 0 {
		return false
	}
	return strings.EqualFold(probe.Runs[0].Tool.Driver.Name, "semgrep")
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	var report sarifReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, fmt.Errorf("semgrep: parse json: %w", err)
	}

	return convert(report), nil
}

func convert(report sarifReport) *domain.NormalizedReport {
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeFilesystem,
		Findings:           nil,
	}

	if len(report.Runs) == 0 {
		return nr
	}

	run := report.Runs[0]

	for _, result := range run.Results {
		rule, hasRule := findRule(run.Tool.Driver.Rules, result.RuleID)
		file := extractFile(result)
		line := extractLine(result)
		location := fmt.Sprintf("%s:%d", file, line)
		fingerprint := "sast:" + result.RuleID + ":" + file + ":" + strconv.Itoa(line)

		nr.Findings = append(nr.Findings, domain.NormalizedFinding{
			Fingerprint: fingerprint,
			FindingKind: "sast",
			Title:       extractTitle(result, rule),
			Description: extractDescription(result, rule),
			Severity:    mapSarifLevel(result.Level, rule),
			Location:    location,
			Dimensions: []domain.Dimension{
				{Key: "rule_id", Value: result.RuleID},
				{Key: "file", Value: file},
				{Key: "line", Value: strconv.Itoa(line)},
			},
			Extensions: resultMeta(result, rule, hasRule),
		})
	}

	return nr
}

// findRule looks up a rule by ID, reporting whether it was present.
func findRule(rules []sarifRule, ruleID string) (sarifRule, bool) {
	for _, r := range rules {
		if r.ID == ruleID {
			return r, true
		}
	}
	return sarifRule{}, false
}

// resultMeta collects scanner-specific extension keys from the rule and the
// result (semgrep emits its own fingerprint/severity/fix properties).
func resultMeta(result sarifResult, rule sarifRule, hasRule bool) map[string]any {
	meta := map[string]any{}
	if hasRule && rule.Properties != nil {
		for _, key := range []string{"cwe", "tags", "precision", "category"} {
			if v, ok := rule.Properties[key]; ok {
				meta[key] = v
			}
		}
	}
	if matchFP, ok := result.Fingerprints["matchBasedFingerprint/v1"]; ok {
		meta["semgrep_fingerprint"] = matchFP
	}
	if result.Properties != nil {
		if sv, ok := result.Properties["severity"]; ok {
			meta["semgrep_severity"] = sv
		}
		if fix, ok := result.Properties["fix"]; ok {
			meta["fix"] = fix
		}
		addResultCWE(meta, result, hasRule)
	}
	return meta
}

// addResultCWE copies the result-level cwe only when the rule did not
// already supply one.
func addResultCWE(meta map[string]any, result sarifResult, hasRule bool) {
	if hasRule || result.Properties == nil {
		return
	}
	if cwe, ok := result.Properties["cwe"]; ok {
		meta["cwe"] = cwe
	}
}

func extractFile(result sarifResult) string {
	if len(result.Locations) == 0 {
		return "unknown"
	}
	uri := result.Locations[0].PhysicalLocation.ArtifactLocation.URI
	if uri == "" {
		return "unknown"
	}
	return uri
}

func extractLine(result sarifResult) int {
	if len(result.Locations) == 0 {
		return 0
	}
	return result.Locations[0].PhysicalLocation.Region.StartLine
}

func extractTitle(result sarifResult, rule sarifRule) string {
	if result.Message.Text != "" {
		return result.Message.Text
	}
	if rule.ID != "" {
		return rule.ID
	}
	return rule.ShortDescription.Text
}

func extractDescription(result sarifResult, rule sarifRule) string {
	if rule.FullDescription.Text != "" {
		return rule.FullDescription.Text
	}
	return rule.ShortDescription.Text
}

func mapSarifLevel(level string, rule sarifRule) domain.Severity {
	switch strings.ToLower(level) {
	case "error":
		return domain.SeverityHigh
	case "warning":
		return domain.SeverityMedium
	case "note":
		return domain.SeverityLow
	case "none":
		return domain.SeverityUnknown
	default:
		if rule.DefaultConfiguration.Level != "" {
			return mapSarifLevel(rule.DefaultConfiguration.Level, sarifRule{})
		}
		return domain.SeverityUnknown
	}
}
