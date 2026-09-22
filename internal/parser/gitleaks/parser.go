// Package gitleaks adapts Gitleaks JSON output to the normalized domain
// model. Gitleaks reports have no severity: every leak ingests as high —
// an exposed credential is actionable until rotated regardless of type.
//
// Redaction: Gitleaks output embeds the matched secret material
// (Secret, Match). The parsed model never carries it — titles use the rule
// description, locations use file and line only. Raw report bytes are
// scrubbed through RedactRaw, which ingest applies before persisting, so
// stored evidence retains provenance (rule, file, commit) without the
// secret itself.
package gitleaks

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/scanner"
)

// redacted replaces secret material in raw evidence.
const redacted = "[REDACTED]"

// Scanner adapts Gitleaks JSON output to the normalized domain model.
type Scanner struct{}

// NewScanner builds the Gitleaks adapter.
func NewScanner() *Scanner { return &Scanner{} }

func (s *Scanner) Descriptor() scanner.Descriptor {
	return scanner.Descriptor{
		Name:                  "gitleaks",
		Version:               "8",
		ContractVersion:       1,
		FingerprintVersion:    1,
		FindingKinds:          []scanner.FindingKind{"secret"},
		ScanTypes:             []domain.ScanType{domain.ScanTypeRepository, domain.ScanTypeFilesystem},
		ProvidesPackages:      false,
		SupportsAutoDetection: true,
	}
}

// SupportsIncremental declares gitleaks safe for incremental analysis
// secret findings map to source files, so a changed-file scan
// covers what it claims to cover.
func (s *Scanner) SupportsIncremental() bool { return true }

func (s *Scanner) DetectFormat(data []byte) bool {
	var probe []gitleaksFinding
	if err := json.Unmarshal(data, &probe); err != nil || len(probe) == 0 {
		return false
	}
	return probe[0].RuleID != "" && probe[0].File != ""
}

func (s *Scanner) Parse(ctx context.Context, data []byte) (*domain.NormalizedReport, error) {
	var findings []gitleaksFinding
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&findings); err != nil {
		return nil, fmt.Errorf("gitleaks: parse json: %w", err)
	}
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: 1,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeRepository,
	}
	for _, g := range findings {
		if g.RuleID == "" || g.File == "" {
			continue
		}
		nr.Findings = append(nr.Findings, convert(g))
	}
	return nr, nil
}

// RedactRaw scrubs secret material from raw Gitleaks evidence, preserving
// every provenance field. Keys marshal in sorted order, so output is
// deterministic. Input that is not a Gitleaks array passes through
// untouched — redaction only applies where the schema is known.
func (s *Scanner) RedactRaw(data []byte) []byte {
	var findings []map[string]any
	if err := json.Unmarshal(data, &findings); err != nil {
		return data
	}
	for _, f := range findings {
		for _, k := range []string{"Secret", "Match"} {
			if v, ok := f[k]; ok {
				if str, ok := v.(string); ok && str != "" {
					f[k] = redacted
				}
			}
		}
	}
	out, err := json.Marshal(findings)
	if err != nil {
		return data
	}
	return out
}

type gitleaksFinding struct {
	Description string   `json:"Description"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	File        string   `json:"File"`
	Commit      string   `json:"Commit"`
	Entropy     float64  `json:"Entropy"`
	RuleID      string   `json:"RuleID"`
	Tags        []string `json:"Tags"`
}

func convert(g gitleaksFinding) domain.NormalizedFinding {
	location := g.File
	if g.StartLine > 0 {
		location = fmt.Sprintf("%s:%d", g.File, g.StartLine)
	}
	title := g.Description
	if title == "" {
		title = g.RuleID
	}
	meta := map[string]any{}
	if g.Commit != "" {
		meta["commit"] = g.Commit
	}
	dims := []domain.Dimension{
		{Key: domain.DimRuleID, Value: g.RuleID},
		{Key: domain.DimFile, Value: g.File},
	}
	if g.StartLine > 0 {
		dims = append(dims, domain.Dimension{Key: domain.DimLine, Value: itoa(g.StartLine)})
	}
	if g.Entropy > 0 {
		meta["entropy"] = g.Entropy
	}
	if len(g.Tags) > 0 {
		meta["tags"] = strings.Join(g.Tags, ",")
	}
	return domain.NormalizedFinding{
		Fingerprint: "secret:" + g.RuleID + ":" + g.File,
		FindingKind: "secret",
		Title:       title,
		Description: "Rotate the exposed credential, revoke the old value, and purge it from history.",
		Severity:    domain.SeverityHigh,
		Location:    location,
		Fix: &domain.FixInfo{
			Summary: "Revoke the exposed credential with its provider, issue a replacement, purge it from VCS history, then resolve this finding. Specht never retrieves or validates secret values.",
		},
		CodeLocation: &domain.CodeLocation{
			File:      g.File,
			StartLine: g.StartLine,
			EndLine:   g.EndLine,
		},
		Dimensions: dims,
		Extensions: meta,
	}
}

func itoa(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", n)
}
