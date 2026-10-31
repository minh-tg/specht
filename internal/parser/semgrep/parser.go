package semgrep

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
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
	// Invocations say whether the run finished. Semgrep writes them when it
	// hit errors.
	Invocations []struct {
		ExecutionSuccessful        *bool `json:"executionSuccessful"`
		ToolExecutionNotifications []struct {
			Level string `json:"level"`
		} `json:"toolExecutionNotifications"`
	} `json:"invocations"`
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
		Name:        "semgrep",
		DisplayName: "Semgrep",
		Formats: []scanner.Format{
			{
				Name:       "JSON",
				Extensions: []string{".json"},
				Command:    `semgrep scan --json -o semgrep.json`,
				TestedWith: "Semgrep 1.172.0",
			},
			{
				Name:       "SARIF",
				Extensions: []string{".json", ".sarif"},
				Command:    `semgrep scan --sarif -o semgrep.sarif`,
				TestedWith: "Semgrep 1.172.0",
				Note:       `Both formats give the same findings.`,
			},
		},
		Version:               "2.1",
		ContractVersion:       1,
		FingerprintVersion:    fingerprintVersion,
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
	for _, run := range probe.Runs {
		name := run.Tool.Driver.Name
		if !strings.EqualFold(name, "semgrep") && !strings.EqualFold(name, "semgrep oss") {
			// A mixed log belongs to the generic SARIF adapter, which reads
			// every run without attributing another tool's results to Semgrep.
			return scanner.NotRecognized
		}
	}
	return scanner.Definite
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

// findingArrays names the arrays of a document that carry findings and
// packages (see scanner.CheckDocument).
var findingArrays = []string{"results", "runs", "rules"}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	budget, err := parseutil.NewBudget(ctx, data, findingArrays...)
	if err != nil {
		return nil, err
	}
	if s.Recognize(data) == scanner.NotRecognized {
		return nil, scanner.Unrecognized("semgrep")
	}
	if shape, ok := parseutil.ReadShape(data); ok && !shape.Has("runs") {
		return parseutil.Hardened(parseNative(budget, data))
	}
	var report sarifReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, scanner.Malformed("semgrep", err)
	}

	return parseutil.Hardened(convert(budget, report))
}

// RedactRaw scrubs matched source from raw Semgrep evidence and caps the
// result at scanner.RawEvidenceCap. Both formats carry the matched code: SARIF
// in a region's snippet, and the native JSON format in extra.lines and in the
// metavars map (captured values such as an abstract_content). Those keys are
// redacted at any depth, and so is the fix key (extra.fix, and the SARIF
// properties.fix): Semgrep fills a rule's fix template with the matched values,
// so a fix that reuses a captured value carries the secret. Data that cannot be
// decoded is an error and no output comes back.
func (s *Scanner) RedactRaw(data []byte) ([]byte, error) {
	return parseutil.RedactRawJSON("semgrep", data, "snippet", "lines", "metavars", "fix")
}

func convert(budget *parseutil.Budget, report sarifReport) (*domain.NormalizedReport, error) {
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: fingerprintVersion,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeFilesystem,
		Findings:           nil,
	}

	if len(report.Runs) == 0 {
		return nr, nil
	}

	var seen []sighting
	var proofs []parseutil.RuleRun
	for _, run := range report.Runs {
		proofs = append(proofs, runProof(run))
		rules := indexRules(run.Tool.Driver.Rules)
		for _, result := range run.Results {
			if err := budget.Add(1); err != nil {
				return nil, err
			}
			rule, hasRule := rules[result.RuleID]
			file := extractFile(result)
			line := extractLine(result)
			message := extractTitle(result, rule)

			seen = append(seen, sighting{
				finding: sastFinding(
					result.RuleID, file, line, message, extractDescription(result, rule),
					mapSarifLevel(result.Level, rule), resultMeta(result, rule, hasRule),
				),
				rule: result.RuleID, file: file, message: message,
				line: line, col: extractColumn(result),
				matchID: matchBasedID(result.Fingerprints["matchBasedId/v1"], result.Fingerprints["matchBasedFingerprint/v1"]),
			})
		}
	}
	nr.Findings = identify(seen)
	nr.ExaminedKeys = parseutil.ExaminedFromRuns(proofs)

	return nr, nil
}

// indexRules maps each rule id to its rule once per run, so looking up the
// rule of a result costs one map read instead of a scan of every rule. When an
// id repeats the first rule wins.
func indexRules(rules []sarifRule) map[string]sarifRule {
	byID := make(map[string]sarifRule, len(rules))
	for _, r := range rules {
		if _, ok := byID[r.ID]; !ok {
			byID[r.ID] = r
		}
	}
	return byID
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
	if id := matchBasedID(result.Fingerprints["matchBasedId/v1"], result.Fingerprints["matchBasedFingerprint/v1"]); id != "" {
		meta["semgrep_fingerprint"] = id
	}
	if result.Properties != nil {
		if sv, ok := result.Properties["severity"]; ok {
			meta["semgrep_severity"] = sv
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
	uri := parseutil.RepoPath(result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
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

// fingerprintVersion is the version of this scanner's identity formula. Version 3
// takes the file relative to the checkout (parseutil.RepoPath), so a scan of an
// absolute directory is the same findings on every runner. Version 2 leaves the
// line out, so a finding keeps its identity when code above it moves.
const fingerprintVersion = 3

// sastFinding builds a finding the same way for both Semgrep output formats. Its
// identity is assigned afterwards by identify, which needs every finding of the
// report to tell identical ones apart.
func sastFinding(ruleID, file string, line int, title, description string, severity domain.Severity, extensions map[string]any) domain.NormalizedFinding {
	return parseutil.HardenFinding(domain.NormalizedFinding{
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
		Col  int `json:"col"`
	} `json:"start"`
	Extra struct {
		Message     string         `json:"message"`
		Severity    string         `json:"severity"`
		Fingerprint string         `json:"fingerprint"`
		Metadata    map[string]any `json:"metadata"`
	} `json:"extra"`
}

// parseNative reads the output of semgrep --json.
func parseNative(budget *parseutil.Budget, data []byte) (*domain.NormalizedReport, error) {
	var report nativeReport
	if err := json.Unmarshal(data, &report); err != nil {
		return nil, scanner.Malformed("semgrep", err)
	}
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: fingerprintVersion,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeFilesystem,
	}
	if n := len(report.Errors); n > 0 {
		// Files Semgrep could not scan are missing from the results, so say so.
		nr.ScanScope = &domain.ScanScope{Ext: map[string]string{"semgrep_errors": strconv.Itoa(n)}}
	}
	var seen []sighting
	for _, r := range report.Results {
		if err := budget.Add(1); err != nil {
			return nil, err
		}
		file := parseutil.RepoPath(r.Path)
		if file == "" {
			file = "unknown"
		}
		title := r.Extra.Message
		if title == "" {
			title = r.CheckID
		}
		line := parseutil.SafeLine(r.Start.Line)
		seen = append(seen, sighting{
			finding: sastFinding(
				r.CheckID, file, line,
				title, r.Extra.Message, mapNativeSeverity(r.Extra.Severity), nativeMeta(r),
			),
			rule: r.CheckID, file: file, message: title,
			line: line, col: r.Start.Col,
			matchID: matchBasedID(r.Extra.Fingerprint),
		})
	}
	nr.Findings = identify(seen)
	return nr, nil
}

// mapNativeSeverity maps a rule's severity in --json output. Rules use the
// current CRITICAL, HIGH, MEDIUM and LOW levels or the legacy ERROR, WARNING
// and INFO ones, and Semgrep reports whichever the rule declares.
func mapNativeSeverity(level string) domain.Severity {
	switch strings.ToUpper(level) {
	case "CRITICAL":
		return domain.SeverityCritical
	case "ERROR", "HIGH":
		return domain.SeverityHigh
	case "WARNING", "MEDIUM":
		return domain.SeverityMedium
	case "INFO", "LOW":
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}

// nativeMeta keeps what the rule says about the finding: the CWE and OWASP
// classes, the category, and how likely, how bad and how sure it is. The fix
// template is left out, for the reason RedactRaw gives: Semgrep fills it with the
// matched values, so it can carry a secret.
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
	return meta
}

func extractColumn(result sarifResult) int {
	if len(result.Locations) == 0 {
		return 0
	}
	return parseutil.SafeLine(result.Locations[0].PhysicalLocation.Region.StartColumn)
}

// sighting is one Semgrep match before it has an identity.
type sighting struct {
	finding             domain.NormalizedFinding
	rule, file, message string
	line, col           int
	matchID             string
}

// matchBasedID returns the first usable match-based id Semgrep wrote. A run that
// is not logged in writes the words "requires login" in its place, which says
// nothing about the match and must not become an identity.
func matchBasedID(candidates ...string) string {
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c != "" && !strings.Contains(strings.ToLower(c), "requires login") {
			return c
		}
	}
	return ""
}

// identify gives every finding of a report its fingerprint, in the order they were seen.
//
// Moving code must not make a finding a new one, so the line is not part of the
// identity. A finding is the rule, the file, and what was matched. What was
// matched is Semgrep's own match-based id when the run has one (a logged-in run),
// and otherwise the message, which names what the rule found (Semgrep fills the
// rule's placeholders in). Two matches that are still alike, the same mistake
// made twice in one file, are told apart by their order in the file, so fixing the
// later one leaves the first one's identity alone.
//
// Both output formats go through here with the same inputs, so a project that
// switches between --sarif and --json keeps its findings.
func identify(seen []sighting) []domain.NormalizedFinding {
	kind := make([]string, len(seen))
	for i, s := range seen {
		if s.matchID != "" {
			kind[i] = "m" + shortHash(s.matchID)
		} else {
			kind[i] = "t" + shortHash(strings.Join(strings.Fields(s.message), " "))
		}
	}

	order := make([]int, len(seen))
	for i := range order {
		order[i] = i
	}
	sort.SliceStable(order, func(a, b int) bool {
		x, y := seen[order[a]], seen[order[b]]
		if x.line != y.line {
			return x.line < y.line
		}
		return x.col < y.col
	})

	ordinal := make(map[string]int, len(seen))
	fingerprints := make([]string, len(seen))
	for _, i := range order {
		s := seen[i]
		identity := "sast:" + s.rule + ":" + s.file + ":" + kind[i]
		n := ordinal[identity]
		ordinal[identity]++
		if n > 0 {
			identity += "#" + strconv.Itoa(n)
		}
		// The rule id is scanner output of any length, and the finding was
		// hardened before it had a fingerprint, so bound it here.
		fingerprints[i] = parseutil.BoundFingerprint(identity)
	}

	out := make([]domain.NormalizedFinding, len(seen))
	for i, s := range seen {
		s.finding.Fingerprint = fingerprints[i]
		out[i] = s.finding
	}
	return out
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
