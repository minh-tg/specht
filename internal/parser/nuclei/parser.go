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

	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/scanner"
)

// Scanner adapts Nuclei JSONL output to the normalized domain model.
type Scanner struct{}

// NewScanner builds the Nuclei adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:                  "nuclei",
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
	line, _, err := splitFirstLine(data)
	if err != nil {
		return false
	}
	var probe nucleiEvent
	if err := json.Unmarshal(line, &probe); err != nil {
		return false
	}
	return probe.TemplateID != "" && probe.Host != ""
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	// A single JSON object or array is also accepted (convenience); the
	// canonical form is one event per line.
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("nuclei: empty input")
	}
	var lines [][]byte
	if trimmed[0] == '[' {
		var arr []json.RawMessage
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return nil, fmt.Errorf("nuclei: parse json array: %w", err)
		}
		for _, l := range arr {
			lines = append(lines, l)
		}
	} else {
		sc := bufio.NewScanner(bytes.NewReader(trimmed))
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			if line := bytes.TrimSpace(sc.Bytes()); len(line) > 0 {
				lines = append(lines, append([]byte{}, line...))
			}
		}
		if err := sc.Err(); err != nil {
			return nil, fmt.Errorf("nuclei: scan lines: %w", err)
		}
	}
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeDAST,
		ScanScope:          &domain.ScanScope{Ext: map[string]string{}},
	}
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
		nr.Findings = append(nr.Findings, convert(ev))
	}
	if skipped > 0 {
		nr.ScanScope.Ext["skipped_lines"] = itoa(skipped)
	}
	if len(nr.ScanScope.Ext) == 0 {
		nr.ScanScope.Ext = nil
	}
	return nr, nil
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
	redact := func(m map[string]any) {
		for _, k := range []string{"request", "response", "extracted-results", "extracted_results"} {
			if v, ok := m[k]; ok {
				if str, ok := v.(string); ok && str != "" {
					m[k] = "[REDACTED]"
				} else if str, ok := v.([]any); ok && len(str) > 0 {
					m[k] = "[REDACTED]"
				}
			}
		}
	}
	if trimmed[0] == '[' {
		var arr []map[string]any
		if err := json.Unmarshal(trimmed, &arr); err != nil {
			return data
		}
		for _, m := range arr {
			redact(m)
		}
		out, err := json.Marshal(arr)
		if err != nil {
			return data
		}
		return out
	}
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
		redact(m)
		out, err := json.Marshal(m)
		if err != nil {
			continue
		}
		arr = append(arr, out)
	}
	out, err := json.Marshal(arr)
	if err != nil {
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
	return domain.NormalizedFinding{
		Fingerprint: "dast:" + ev.TemplateID + ":" + identity,
		FindingKind: "dast",
		Title:       title,
		Description: ev.Info.Description,
		Severity:    normalizeSeverity(ev.Info.Severity),
		Location:    target,
		Dimensions:  dims,
		Extensions:  meta,
	}
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
