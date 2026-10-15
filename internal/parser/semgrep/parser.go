package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
	"github.com/minh-tg/specht/internal/scanner"
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
// SAST findings map to source files, so a changed-file scan
// covers what it claims to cover.
func (s *Scanner) SupportsIncremental() bool { return true }

func (s *Scanner) DetectFormat(data []byte) bool {
	return s.Recognize(data) == scanner.Definite
}

// Recognize grades a document. A SARIF log whose first run names Semgrep is
// definite. SARIF from another tool belongs to the generic sarif scanner.
func (s *Scanner) Recognize(data []byte) scanner.Recognition {
	shape, ok := parseutil.ReadShape(data)
	if !ok || !shape.IsObject() {
		return scanner.NotRecognized
	}
	if shape.Has("runs") {
		return recognizeSARIF(data)
	}
	return recognizeNative(shape)
}

// recognizeSARIF is definite for a log whose first run names Semgrep. SARIF
// from another tool belongs to the generic sarif scanner.
func recognizeSARIF(data []byte) scanner.Recognition {
	var probe struct {
		Runs []struct {
			Tool struct {
				Driver struct {
					Name string `json:"name"`
				} `json:"driver"`
			} `json:"tool"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &probe); err != nil || len(probe.Runs) == 0 {
		return scanner.NotRecognized
	}
	name := probe.Runs[0].Tool.Driver.Name
	if strings.EqualFold(name, "semgrep") || strings.EqualFold(name, "semgrep oss") {
		return scanner.Definite
	}
	return scanner.NotRecognized
}

// recognizeNative is definite for results that carry a check id and a path,
// and for a clean report, which Semgrep writes with an empty results list next
// to its errors and paths blocks. Other tools use the key "results" too, so a
// bare empty list is not enough.
func recognizeNative(shape parseutil.Shape) scanner.Recognition {
	results, present := shape.List("results")
	if !present {
		return scanner.NotRecognized
	}
	for _, r := range results {
		if parseutil.ObjectHas(r, "check_id", "path") {
			return scanner.Definite
		}
	}
	if len(results) == 0 && shape.Has("errors") && shape.Has("paths") {
		return scanner.Definite
	}
	return scanner.NotRecognized
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	if s.Recognize(data) == scanner.NotRecognized {
		return nil, scanner.Unrecognized("semgrep")
	}
	if shape, ok := parseutil.ReadShape(data); ok && !shape.Has("runs") {
		return parseNative(data)
	}
	var report sarifReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, scanner.Malformed("semgrep", err)
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

		nr.Findings = append(nr.Findings, sastFinding(
			result.RuleID, file, line,
			extractTitle(result, rule), extractDescription(result, rule),
			mapSarifLevel(result.Level, rule), resultMeta(result, rule, hasRule),
		))
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
	uri := parseutil.CleanFilePath(result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	if uri == "" {
		return "unknown"
	}
	return uri
}

func extractLine(result sarifResult) int {
	if len(result.Locations) == 0 {
		return 0
	}
	return parseutil.SafeLine(result.Locations[0].PhysicalLocation.Region.StartLine)
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

// sastFinding builds a finding the same way for both Semgrep output formats.
// The identity is the rule, the file and the line, so a scan read from SARIF
// and the same scan read from --json are the same findings.
func sastFinding(ruleID, file string, line int, title, description string, severity domain.Severity, extensions map[string]any) domain.NormalizedFinding {
	return parseutil.HardenFinding(domain.NormalizedFinding{
		Fingerprint: "sast:" + ruleID + ":" + file + ":" + strconv.Itoa(line),
		FindingKind: "sast",
		Title:       title,
		Description: description,
		Severity:    severity,
		Location:    fmt.Sprintf("%s:%d", file, line),
		Dimensions: []domain.Dimension{
			{Key: "rule_id", Value: ruleID},
			{Key: "file", Value: file},
			{Key: "line", Value: strconv.Itoa(line)},
		},
		Extensions: extensions,
	})
}

type nativeReport struct {
	Results []nativeResult    `json:"results"`
	Errors  []json.RawMessage `json:"errors"`
}

type nativeResult struct {
	CheckID string `json:"check_id"`
	Path    string `json:"path"`
	Start   struct {
		Line int `json:"line"`
	} `json:"start"`
	Extra struct {
		Message  string         `json:"message"`
		Severity string         `json:"severity"`
		Fix      string         `json:"fix"`
		Metadata map[string]any `json:"metadata"`
	} `json:"extra"`
}

// parseNative reads the output of semgrep --json.
func parseNative(data []byte) (*domain.NormalizedReport, error) {
	var report nativeReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, scanner.Malformed("semgrep", err)
	}
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeFilesystem,
	}
	if n := len(report.Errors); n > 0 {
		// Files Semgrep could not scan are missing from the results, so say so.
		nr.ScanScope = &domain.ScanScope{Ext: map[string]string{"semgrep_errors": strconv.Itoa(n)}}
	}
	for _, r := range report.Results {
		file := parseutil.CleanFilePath(r.Path)
		if file == "" {
			file = "unknown"
		}
		title := r.Extra.Message
		if title == "" {
			title = r.CheckID
		}
		nr.Findings = append(nr.Findings, sastFinding(
			r.CheckID, file, parseutil.SafeLine(r.Start.Line),
			title, r.Extra.Message, mapNativeSeverity(r.Extra.Severity), nativeMeta(r),
		))
	}
	return nr, nil
}

func mapNativeSeverity(level string) domain.Severity {
	switch strings.ToUpper(level) {
	case "ERROR":
		return domain.SeverityHigh
	case "WARNING":
		return domain.SeverityMedium
	case "INFO":
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}

// nativeMeta keeps what the rule says about the finding: the CWE and OWASP
// classes, the category, and how likely, how bad and how sure it is.
func nativeMeta(r nativeResult) map[string]any {
	meta := map[string]any{}
	for _, key := range []string{"cwe", "owasp", "category", "confidence", "impact", "likelihood"} {
		if v, ok := r.Extra.Metadata[key]; ok {
			meta[key] = v
		}
	}
	if r.Extra.Severity != "" {
		meta["semgrep_severity"] = r.Extra.Severity
	}
	if r.Extra.Fix != "" {
		meta["fix"] = r.Extra.Fix
	}
	return meta
}
