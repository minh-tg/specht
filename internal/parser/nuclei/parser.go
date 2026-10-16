// Package nuclei adapts Nuclei JSONL output to the normalized domain
// model. Each line is one observation: template + matched URL. Identity is
// template + URL without query or fragment, so parameter fuzzing never
// forks rows; tested parameter names (never values) ride as dimensions.
//
// Redaction: Nuclei events embed request/response bodies and extracted
// results, which routinely contain credentials and PII. None of them enter
// the parsed model, and RedactRaw strips them from stored raw evidence
// (provenance — template, host, severity, references — survives).
// Nuclei emits no stable per-finding fingerprint; repeated scans of the
// same template + URL converge on the identity above.
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
	"github.com/minh-tg/specht/internal/scanner"
)

// Scanner adapts Nuclei JSONL output to the normalized domain model.
type Scanner struct{}

// NewScanner builds the Nuclei adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:        "nuclei",
		DisplayName: "Nuclei",
		Formats: []scanner.Format{
			{
				Name:       "JSON Lines",
				Extensions: []string{".jsonl", ".ndjson"},
				Command:    `nuclei -u https://example.com -jsonl -o nuclei.jsonl`,
				TestedWith: "Nuclei 3.11.1",
				Note:       `One finding per template and URL.`,
			},
		},
		Version:               "3",
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          []scanner.FindingKind{"dast"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeDAST},
		ProvidesPackages:      false,
		SupportsAutoDetection: true,
	}
}

func (s *Scanner) DetectFormat(data []byte) bool {
	return s.Recognize(data) == scanner.Definite
}

// Recognize grades a document. Nuclei writes one event per line, or a list of
// events when they arrive as a JSON array; an event has a template id and a
// host. An empty list is possible, since a scan with no matches writes nothing.
func (s *Scanner) Recognize(data []byte) scanner.Recognition {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return scanner.NotRecognized
	}
	if trimmed[0] == '[' {
		var events []json.RawMessage
		if err := json.Unmarshal(trimmed, &events); err != nil {
			return scanner.NotRecognized
		}
		if len(events) == 0 {
			return scanner.Possible
		}
		for _, ev := range events[:min(len(events), recognizeEvents)] {
			if parseutil.ObjectHas(ev, "template-id", "host") {
				return scanner.Definite
			}
		}
		return scanner.NotRecognized
	}
	// One event per line. A line that is not an event is skipped when parsing,
	// so the first few lines decide rather than only the first.
	lines := bufio.NewScanner(bytes.NewReader(trimmed))
	lines.Buffer(make([]byte, 1024*1024), 1024*1024)
	for i := 0; i < recognizeEvents && lines.Scan(); i++ {
		if parseutil.ObjectHas(bytes.TrimSpace(lines.Bytes()), "template-id", "host") {
			return scanner.Definite
		}
	}
	return scanner.NotRecognized
}

// recognizeEvents bounds how many events Recognize inspects.
const recognizeEvents = 100

// splitNucleiLines normalizes Nuclei input (JSON array or JSONL) into raw
// event lines.
func splitNucleiLines(trimmed []byte) ([][]byte, error) {
	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("nuclei: parse json array: %w", err)
		}
		lines := make([][]byte, 0, len(arr))
		for _, l := range arr {
			lines = append(lines, l)
		}
		return lines, nil
	}
	sc := bufio.NewScanner(bytes.NewReader(trimmed))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	var lines [][]byte
	for sc.Scan() {
		if line := bytes.TrimSpace(sc.Bytes()); len(line) > 0 {
			lines = append(lines, append([]byte{}, line...))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, scanner.Malformed("nuclei", fmt.Errorf("scan lines: %w", err))
	}
	return lines, nil
}

// appendNucleiFindings decodes event lines into findings, returning the
// skipped-line count.
func appendNucleiFindings(budget *parseutil.Budget, nr *domain.NormalizedReport, lines [][]byte) (int, error) {
	skipped := 0
	for _, line := range lines {
		var ev nucleiEvent
		if err := json.Unmarshal(line, &ev); err != nil {
			skipped++
			continue
		}
		if ev.TemplateID == "" || ev.Host == "" {
			skipped++
			continue
		}
		if err := budget.Add(1); err != nil {
			return 0, err
		}
		nr.Findings = append(nr.Findings, convert(ev))
	}
	return skipped, nil
}

// findingArrays names the arrays of a document that carry findings and
// packages (see scanner.CheckDocument).
var findingArrays = []string{""}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	budget, err := parseutil.NewBudget(ctx, data, findingArrays...)
	if err != nil {
		return nil, err
	}
	if s.Recognize(data) == scanner.NotRecognized {
		return nil, scanner.Unrecognized("nuclei")
	}
	// A single JSON object or array is also accepted (convenience); the
	// canonical form is one event per line.
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("nuclei: empty input")
	}
	lines, err := splitNucleiLines(trimmed)
	if err != nil {
		return nil, err
	}
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeDAST,
		ScanScope:          &domain.ScanScope{Ext: map[string]string{}},
	}
	skipped, err := appendNucleiFindings(budget, nr, lines)
	if err != nil {
		return nil, err
	}
	if skipped > 0 {
		nr.ScanScope.Ext["skipped_lines"] = itoa(skipped)
	}
	if len(nr.ScanScope.Ext) == 0 {
		nr.ScanScope.Ext = nil
	}
	return parseutil.HardenReport(nr), nil
}

// redactedFields are the keys of a Nuclei event that hold request and response
// bodies or extracted values. They are matched without regard to case and at
// any depth.
var redactedFields = []string{"request", "response", "extracted-results", "extracted_results"}

// redactNucleiFields replaces sensitive embedded payloads in one decoded
// Nuclei event with the redaction marker.
func redactNucleiFields(m map[string]any) {
	parseutil.RedactKeys(m, "[REDACTED]", redactedFields...)
}

// redactNucleiArray redacts a JSON-array Nuclei payload, reporting whether
// the input had array form.
func redactNucleiArray(trimmed []byte) ([]byte, bool, bool) {
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, false, false
	}
	var arr []map[string]any
	if err := json.Unmarshal(trimmed, &arr); err != nil {
		return nil, true, false
	}
	for _, m := range arr {
		redactNucleiFields(m)
	}
	out, err := json.Marshal(arr)
	if err != nil {
		return nil, true, false
	}
	return out, true, true
}

// redactNucleiLines redacts JSONL Nuclei payloads into a storable array.
func redactNucleiLines(trimmed []byte) ([]byte, bool) {
	var arr []json.RawMessage
	sc := bufio.NewScanner(bytes.NewReader(trimmed))
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var m map[string]any
		if err := json.Unmarshal(line, &m); err != nil {
			continue
		}
		redactNucleiFields(m)
		out, err := json.Marshal(m)
		if err != nil {
			continue
		}
		arr = append(arr, out)
	}
	if err := sc.Err(); err != nil {
		// A line over the scanner buffer ended the scan; storing what was read
		// would drop the rest of the evidence without a word.
		return nil, false
	}
	out, err := json.Marshal(arr)
	if err != nil {
		return nil, false
	}
	return out, true
}

// RedactRaw strips request/response bodies and extracted results from
// Nuclei evidence and returns storable JSON: JSONL input becomes one JSON
// array (raw evidence columns require valid JSON). Provenance fields
// survive; unparseable input passes through untouched.
func (s *Scanner) RedactRaw(data []byte) []byte {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return data
	}
	if out, isArray, ok := redactNucleiArray(trimmed); isArray {
		if !ok {
			return data
		}
		return out
	}
	out, ok := redactNucleiLines(trimmed)
	if !ok {
		return data
	}
	return out
}

type nucleiEvent struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name        string   `json:"name"`
		Description string   `json:"description"`
		Reference   []string `json:"reference"`
		Severity    string   `json:"severity"`
		Tags        []string `json:"tags"`
	} `json:"info"`
	Host      string `json:"host"`
	MatchedAt string `json:"matched-at"`
	Type      string `json:"type"`
}

func convert(ev nucleiEvent) domain.NormalizedFinding {
	target := ev.MatchedAt
	if target == "" {
		target = ev.Host
	}
	identity, params := identityURL(target)
	title := ev.Info.Name
	if title == "" {
		title = ev.TemplateID
	}
	var dims []domain.Dimension
	dims = append(dims,
		domain.Dimension{Key: domain.DimRuleID, Value: ev.TemplateID},
		domain.Dimension{Key: domain.DimURL, Value: identity},
	)
	for _, p := range params {
		dims = append(dims, domain.Dimension{Key: domain.DimParameter, Value: p})
	}
	meta := map[string]any{}
	if len(ev.Info.Tags) > 0 {
		meta["tags"] = strings.Join(ev.Info.Tags, ",")
	}
	if len(ev.Info.Reference) > 0 {
		meta["references"] = ev.Info.Reference
	}
	if ev.Type != "" {
		meta["nuclei_type"] = ev.Type
	}
	cleanLoc := parseutil.CleanFilePath(target)
	if cleanLoc == "" {
		cleanLoc = parseutil.SanitizeText(target, parseutil.MaxPathLength)
	}
	return parseutil.HardenFinding(domain.NormalizedFinding{
		Fingerprint: "dast:" + ev.TemplateID + ":" + identity,
		FindingKind: "dast",
		Title:       title,
		Description: ev.Info.Description,
		Severity:    normalizeSeverity(ev.Info.Severity),
		Location:    cleanLoc,
		Dimensions:  dims,
		Extensions:  meta,
	})
}

// identityURL normalizes an observed URL to scheme://host/path (no query,
// no fragment) and returns the sorted query parameter names.
func identityURL(raw string) (string, []string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw, nil
	}
	var params []string
	seen := map[string]bool{}
	for k := range u.Query() {
		if !seen[k] {
			seen[k] = true
			params = append(params, k)
		}
	}
	sort.Strings(params)
	u.RawQuery, u.Fragment = "", ""
	return u.String(), params
}

func normalizeSeverity(s string) domain.Severity {
	switch strings.ToLower(s) {
	case "critical":
		return domain.SeverityCritical
	case "high":
		return domain.SeverityHigh
	case "medium":
		return domain.SeverityMedium
	case "low", "info":
		return domain.SeverityLow
	default:
		return domain.SeverityUnknown
	}
}

func splitFirstLine(data []byte) ([]byte, bool, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, false, fmt.Errorf("empty")
	}
	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, false, err
		}
		if len(arr) == 0 {
			return nil, false, fmt.Errorf("empty")
		}
		return arr[0], true, nil
	}
	if i := bytes.IndexByte(trimmed, '\n'); i >= 0 {
		return trimmed[:i], true, nil
	}
	return trimmed, true, nil
}

func itoa(n int) string {
	return fmt.Sprintf("%d", n)
}
