// Package sarif is the universal SARIF adapter: any SARIF 2.1.0 producer
// (CodeQL, Semgrep, Bandit, tfsec-via-SARIF, …) ingests through one path.
// It complements the tool-specific adapters (e.g. semgrep), which keep
// their own fingerprint formulas and stable identities: adding this adapter
// changes no existing finding identity.
//
// Universal semantics, applied identically to every run in the document:
//   - All runs are converted (multi-tool documents keep every run); each
//     finding records its producer run's tool name in extensions.
//   - Identity prefers producer partialFingerprints (stable across line
//     shifts), falling back to rule + file. Lines never enter the
//     fingerprint; SAST correlation keys match on rule + file.
//   - Severity: result level, then the rule's defaultConfiguration level,
//     then a numeric security-severity property, else unknown.
//   - Results with an accepted suppression are skipped (triaged in the
//     producing tool); other suppressions and the baseline state are kept
//     as extensions. Skipped results are counted, never silent.
//   - The first fix description becomes FixInfo.Summary; CWE ids from rule
//     relationships and taxonomies land in extensions under the tool
//     namespace. Unsupported fields are ignored by the JSON decoder
//     without dropping usable results.
//   - Findings without any location are kept with an "(unknown)" file and
//     no file/line dimensions rather than dropped.
//   - Every finding is SAST. SARIF carries no finding-kind field and the
//     adapter does not guess: IaC and secret producers keep their native
//     adapters (checkov, trivy) or a future dedicated SARIF-kind adapter.
package sarif

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

const unknownFile = "(unknown)"

// Scanner adapts SARIF 2.1.0 output to the normalized domain model.
type Scanner struct{}

// NewScanner builds the universal SARIF adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:                  "sarif",
		Version:               "2.1.0",
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          []scanner.FindingKind{"sast"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeFilesystem, domain.ScanTypeRepository},
		ProvidesPackages:      false,
		SupportsAutoDetection: true,
	}
}

func (s *Scanner) DetectFormat(data []byte) bool {
	var probe sarifLog
	if err := json.Unmarshal(data, &probe); err != nil {
		return false
	}
	return strings.HasPrefix(probe.Version, "2.1") && len(probe.Runs) > 0
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	var log sarifLog
	if err := json.Unmarshal(data, &log); err != nil {
		return nil, fmt.Errorf("sarif: parse json: %w", err)
	}
	if log.Version != "" && !strings.HasPrefix(log.Version, "2.1") {
		return nil, fmt.Errorf("sarif: unsupported version %q (want 2.1.x)", log.Version)
	}
	return convert(log), nil
}

type sarifLog struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name          string      `json:"name"`
			Version       string      `json:"version"`
			Rules         []sarifRule `json:"rules"`
			Notifications []any       `json:"notifications"`
		} `json:"driver"`
	} `json:"tool"`
	Invocations []struct {
		ExecutionSuccessful bool `json:"executionSuccessful"`
	} `json:"invocations"`
	Taxonomies []struct {
		Name     string `json:"name"`
		FullName string `json:"fullName"`
	} `json:"taxonomies"`
	Results []sarifResult `json:"results"`
}

type sarifRule struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	ShortDescription struct {
		Text string `json:"text"`
	} `json:"shortDescription"`
	FullDescription struct {
		Text string `json:"text"`
	} `json:"fullDescription"`
	DefaultConfiguration struct {
		Level string `json:"level"`
	} `json:"defaultConfiguration"`
	Relationships []sarifRelationship `json:"relationships"`
	Properties    map[string]any      `json:"properties"`
}

type sarifRelationship struct {
	Target struct {
		ID string `json:"id"`
	} `json:"target"`
	Kinds []string `json:"kinds"`
}

type sarifResult struct {
	RuleID    string `json:"ruleId"`
	RuleIndex *int   `json:"ruleIndex"`
	Level     string `json:"level"`
	Message   struct {
		Text string `json:"text"`
	} `json:"message"`
	Locations           []sarifLocation   `json:"locations"`
	PartialFingerprints map[string]string `json:"partialFingerprints"`
	Fingerprints        map[string]string `json:"fingerprints"`
	Suppressions        []struct {
		Kind   string `json:"kind"`
		Status string `json:"status"`
	} `json:"suppressions"`
	BaselineState string `json:"baselineState"`
	Fixes         []struct {
		Description struct {
			Text string `json:"text"`
		} `json:"description"`
	} `json:"fixes"`
	Properties map[string]any `json:"properties"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region struct {
			StartLine int `json:"startLine"`
		} `json:"region"`
	} `json:"physicalLocation"`
}

func convert(log sarifLog) *domain.NormalizedReport {
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeFilesystem,
		ScanScope:          &domain.ScanScope{Ext: map[string]string{}},
	}
	skipped := 0
	for _, run := range log.Runs {
		tool := run.Tool.Driver.Name
		if tool == "" {
			tool = "sarif"
		}
		ns := extensionNS(tool)
		if len(nr.ScanScope.Ext) == 0 && run.Tool.Driver.Version != "" {
			nr.ScanScope.Ext[ns+"_tool_version"] = run.Tool.Driver.Version
		}
		rules := indexRules(run.Tool.Driver.Rules)
		for _, result := range run.Results {
			rule, ruleID := resolveRule(run.Tool.Driver.Rules, rules, result)
			if ruleID == "" || suppressedAccepted(result) {
				skipped++
				continue
			}
			nr.Findings = append(nr.Findings, parseutil.HardenFinding(convertResult(result, rule, ruleID, ns)))
		}
	}
	if skipped > 0 {
		nr.ScanScope.Ext["skipped_results"] = strconv.Itoa(skipped)
	}
	if len(nr.ScanScope.Ext) == 0 {
		nr.ScanScope.Ext = nil
	}
	return nr
}

// indexRules indexes rules by ID, keeping the first occurrence.
func indexRules(rules []sarifRule) map[string]sarifRule {
	byID := map[string]sarifRule{}
	for _, r := range rules {
		if _, ok := byID[r.ID]; !ok && r.ID != "" {
			byID[r.ID] = r
		}
	}
	return byID
}

// resolveRule maps a result to its rule and effective rule ID. Results with
// no resolvable ID are reported with an empty ID for the caller to skip.
func resolveRule(rules []sarifRule, byID map[string]sarifRule, result sarifResult) (sarifRule, string) {
	rule := byID[result.RuleID]
	if rule.ID == "" && result.RuleIndex != nil && *result.RuleIndex >= 0 && *result.RuleIndex < len(rules) {
		rule = rules[*result.RuleIndex]
	}
	ruleID := result.RuleID
	if ruleID == "" {
		ruleID = rule.ID
	}
	return rule, ruleID
}

func convertResult(result sarifResult, rule sarifRule, ruleID, ns string) domain.NormalizedFinding {
	file := resultFile(result)
	line := resultLine(result)
	fingerprint := "sast:" + ruleID + ":" + file
	if fp := stableProducerFingerprint(result); fp != "" {
		fingerprint += ":" + fp
	}
	location := file
	if line > 0 {
		location = fmt.Sprintf("%s:%d", file, line)
	}

	title := result.Message.Text
	if title == "" {
		title = ruleID
	}
	description := rule.FullDescription.Text
	if description == "" {
		description = rule.ShortDescription.Text
	}

	f := domain.NormalizedFinding{
		Fingerprint: fingerprint,
		FindingKind: "sast",
		Title:       title,
		Description: description,
		Severity:    severityFor(result, rule),
		Location:    location,
		Fix:         resultFix(result),
		Dimensions:  resultDims(ruleID, file, line),
		Extensions:  resultMeta(result, rule, ns),
	}
	if file != unknownFile {
		f.CodeLocation = &domain.CodeLocation{File: file, StartLine: line}
	}
	return f
}

// resultDims builds the stable dimension set for a SARIF result.
func resultDims(ruleID, file string, line int) []domain.Dimension {
	dims := []domain.Dimension{{Key: domain.DimRuleID, Value: ruleID}}
	if file == unknownFile {
		return dims
	}
	dims = append(dims, domain.Dimension{Key: domain.DimFile, Value: file})
	if line > 0 {
		dims = append(dims, domain.Dimension{Key: domain.DimLine, Value: strconv.Itoa(line)})
	}
	return dims
}

// resultMeta collects producer-specific extension keys from the rule and
// result (properties, fingerprints, suppressions, baseline state).
func resultMeta(result sarifResult, rule sarifRule, ns string) map[string]any {
	meta := map[string]any{ns + "_tool": ns}
	if cwes := cweIDs(rule); len(cwes) > 0 {
		meta["cwe"] = cwes
	}
	for _, k := range []string{"precision", "recall", "tags", "category", "severity"} {
		if v, ok := rule.Properties[k]; ok {
			meta[ns+"_"+k] = v
		}
	}
	if v, ok := result.Properties["severity"]; ok {
		meta[ns+"_severity"] = v
	}
	for k, v := range result.Fingerprints {
		meta[ns+"_fingerprint_"+sanitize(k)] = v
	}
	if len(result.Suppressions) > 0 {
		var kinds []string
		for _, s := range result.Suppressions {
			kinds = append(kinds, s.Kind+"/"+s.Status)
		}
		meta["suppressions"] = kinds
	}
	if result.BaselineState != "" {
		meta["baseline_state"] = result.BaselineState
	}
	return meta
}

// resultFix extracts the first non-empty fix description.
func resultFix(result sarifResult) *domain.FixInfo {
	if len(result.Fixes) == 0 || result.Fixes[0].Description.Text == "" {
		return nil
	}
	return &domain.FixInfo{Summary: result.Fixes[0].Description.Text}
}

func resultFile(result sarifResult) string {
	if len(result.Locations) == 0 {
		return unknownFile
	}
	uri := parseutil.CleanFilePath(result.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	if uri == "" {
		return unknownFile
	}
	return uri
}

func resultLine(result sarifResult) int {
	if len(result.Locations) == 0 {
		return 0
	}
	return parseutil.SafeLine(result.Locations[0].PhysicalLocation.Region.StartLine)
}

// stableProducerFingerprint prefers tool-computed partial fingerprints over
// anything positional. Keys sort so the choice is deterministic.
func stableProducerFingerprint(result sarifResult) string {
	if len(result.PartialFingerprints) == 0 {
		return ""
	}
	keys := make([]string, 0, len(result.PartialFingerprints))
	for k := range result.PartialFingerprints {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	// hash.Hash.Write is specified never to return an error.
	for _, k := range keys {
		_, _ = fmt.Fprintf(h, "%s=%s;", k, result.PartialFingerprints[k])
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func suppressedAccepted(result sarifResult) bool {
	for _, s := range result.Suppressions {
		if strings.EqualFold(s.Status, "accepted") {
			return true
		}
	}
	return false
}

func severityFor(result sarifResult, rule sarifRule) domain.Severity {
	if s, ok := mapLevel(result.Level); ok {
		return s
	}
	if s, ok := mapLevel(rule.DefaultConfiguration.Level); ok {
		return s
	}
	if v, ok := rule.Properties["security-severity"]; ok {
		if f, ok := numeric(v); ok {
			return securitySeverityRank(f)
		}
	}
	return domain.SeverityUnknown
}

func mapLevel(level string) (domain.Severity, bool) {
	switch strings.ToLower(level) {
	case "error":
		return domain.SeverityHigh, true
	case "warning":
		return domain.SeverityMedium, true
	case "note":
		return domain.SeverityLow, true
	case "none":
		return domain.SeverityUnknown, true
	default:
		return domain.SeverityUnknown, false
	}
}

// securitySeverityRank maps a 0-10 security score (CodeQL convention) to a
// severity rank.
func securitySeverityRank(score float64) domain.Severity {
	switch {
	case score >= 9:
		return domain.SeverityCritical
	case score >= 7:
		return domain.SeverityHigh
	case score >= 4:
		return domain.SeverityMedium
	case score > 0:
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}

func numeric(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// cweIDs collects CWE identifiers from rule relationships (kind relevant
// or kind missing) plus a plain cwe property.
func cweIDs(rule sarifRule) []string {
	var out []string
	seen := map[string]bool{}
	add := func(id string) {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			return
		}
		seen[id] = true
		out = append(out, id)
	}
	for _, rel := range rule.Relationships {
		if isRelevantCWE(rel) {
			add(rel.Target.ID)
		}
	}
	addPropertyCWEs(rule, add)
	sort.Strings(out)
	return out
}

// isRelevantCWE reports whether a rule relationship points at a CWE that is
// kind-relevant (or declares no kinds at all).
func isRelevantCWE(rel sarifRelationship) bool {
	if !strings.HasPrefix(rel.Target.ID, "CWE-") {
		return false
	}
	for _, k := range rel.Kinds {
		if strings.EqualFold(k, "relevant") {
			return true
		}
	}
	return len(rel.Kinds) == 0
}

// addPropertyCWEs feeds every string in the cwe rule property to add.
func addPropertyCWEs(rule sarifRule, add func(string)) {
	switch v := rule.Properties["cwe"].(type) {
	case string:
		add(v)
	case []any:
		for _, e := range v {
			if s, ok := e.(string); ok {
				add(s)
			}
		}
	}
}

// extensionNS namespaces producer-specific extensions by tool name.
func extensionNS(tool string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(tool) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "sarif"
	}
	return b.String()
}

func sanitize(s string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			return r
		}
		return '_'
	}, s)
}
