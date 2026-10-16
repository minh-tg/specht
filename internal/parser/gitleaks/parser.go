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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"
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
		Name:        "gitleaks",
		DisplayName: "Gitleaks",
		Formats: []scanner.Format{
			{
				Name:       "JSON",
				Extensions: []string{".json"},
				Command:    `gitleaks detect --report-format json --report-path gitleaks.json`,
				TestedWith: "Gitleaks 8.30.1",
				Note:       "Reports written with `--redact` are accepted.",
			},
		},
		Version:               "8",
		ContractVersion:       1,
		FingerprintVersion:    fingerprintVersion,
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
	return s.Recognize(data) == scanner.Definite
}

// Recognize grades a document. Gitleaks writes a list of findings, each with a
// rule id and a file. A report with no leaks is an empty list (or null), which
// is possible but not certain.
func (s *Scanner) Recognize(data []byte) scanner.Recognition {
	shape, ok := parseutil.ReadShape(data)
	if !ok {
		return scanner.NotRecognized
	}
	if shape.IsNull() {
		return scanner.Possible
	}
	if !shape.IsArray() {
		return scanner.NotRecognized
	}
	if len(shape.Array) == 0 {
		return scanner.Possible
	}
	if parseutil.ObjectHas(shape.Array[0], "RuleID", "File") {
		return scanner.Definite
	}
	return scanner.NotRecognized
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
		return nil, scanner.Unrecognized("gitleaks")
	}
	var findings []gitleaksFinding
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&findings); err != nil {
		return nil, scanner.Malformed("gitleaks", err)
	}
	nr := &domain.NormalizedReport{
		ContractVersion:    1,
		FingerprintVersion: fingerprintVersion,
		Completeness:       domain.CompletenessUnknown,
		ScanType:           domain.ScanTypeRepository,
	}
	key, _ := scanner.FingerprintKey(ctx)
	for _, g := range findings {
		if g.RuleID == "" || g.File == "" {
			continue
		}
		if err := budget.Add(1); err != nil {
			return nil, err
		}
		f, err := convert(g, key)
		if err != nil {
			return nil, err
		}
		nr.Findings = append(nr.Findings, parseutil.HardenFinding(f))
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
	// Secret is the matched credential. It is read only to be hashed into the
	// finding's identity and is never copied into the parsed model.
	Secret      string   `json:"Secret"`
	Fingerprint string   `json:"Fingerprint"`
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

func convert(g gitleaksFinding, key []byte) (domain.NormalizedFinding, error) {
	file := parseutil.CleanFilePath(g.File)
	if file == "" {
		file = "unknown"
	}
	startLine := parseutil.SafeLine(g.StartLine)
	endLine := parseutil.SafeLine(g.EndLine)
	if endLine < startLine {
		endLine = startLine
	}
	location := file
	if startLine > 0 {
		location = fmt.Sprintf("%s:%d", file, startLine)
	}
	title := g.Description
	if title == "" {
		title = g.RuleID
	}
	identity, basis, err := identityOf(g, file, key)
	if err != nil {
		return domain.NormalizedFinding{}, err
	}
	meta := map[string]any{"identity_basis": basis}
	if g.Commit != "" {
		meta["commit"] = g.Commit
	}
	dims := []domain.Dimension{
		{Key: domain.DimRuleID, Value: g.RuleID},
		{Key: domain.DimFile, Value: file},
	}
	if startLine > 0 {
		dims = append(dims, domain.Dimension{Key: domain.DimLine, Value: itoa(startLine)})
	}
	if g.Entropy > 0 {
		meta["entropy"] = g.Entropy
	}
	if len(g.Tags) > 0 {
		meta["tags"] = strings.Join(g.Tags, ",")
	}
	return domain.NormalizedFinding{
		Fingerprint: "secret:" + g.RuleID + ":" + file + ":" + identity,
		FindingKind: "secret",
		Title:       title,
		Description: "Rotate the exposed credential, revoke the old value, and purge it from history.",
		Severity:    domain.SeverityHigh,
		Location:    location,
		Fix: &domain.FixInfo{
			Summary: "Revoke the exposed credential with its provider, issue a replacement, purge it from VCS history, then resolve this finding. Specht never retrieves or validates secret values.",
		},
		CodeLocation: &domain.CodeLocation{
			File:      file,
			StartLine: startLine,
			EndLine:   endLine,
		},
		Dimensions: dims,
		Extensions: meta,
	}, nil
}

func itoa(n int) string {
	if n <= 0 {
		return ""
	}
	return fmt.Sprintf("%d", n)
}

// fingerprintVersion is the version of this scanner's identity formula. Version 2
// tells two secrets of one rule in one file apart; version 1 merged them.
const fingerprintVersion = 2

// UsesFingerprintKey says this scanner hashes secrets with the instance key.
func (s *Scanner) UsesFingerprintKey() bool { return true }

// identityOf says which part of a finding makes it that finding, and how it was
// found. The identity is the rule, the file and a digest of the credential, so
// two different keys in one file are two findings, the same key stays one
// finding when its line moves or when many commits contain it, and a rotated key
// is a new one. The digest is keyed (HMAC-SHA-256 with the instance key), so
// someone who can read the database cannot test guesses against it, and the
// credential itself is never stored.
//
// A report written with --redact has no credential to hash. Gitleaks' own
// fingerprint (commit, file, rule, line) then tells findings apart, and failing
// that the line does. Neither needs the key, and the basis is recorded.
func identityOf(g gitleaksFinding, file string, key []byte) (digest, basis string, err error) {
	if secret := strings.TrimSpace(g.Secret); secret != "" && !isRedacted(secret) {
		if len(key) == 0 {
			return "", "", scanner.KeyRequired("gitleaks")
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(g.RuleID + "\x00" + file + "\x00" + secret))
		return hex.EncodeToString(mac.Sum(nil))[:32], "secret", nil
	}
	if fp := strings.TrimSpace(g.Fingerprint); fp != "" {
		sum := sha256.Sum256([]byte(fp))
		return hex.EncodeToString(sum[:])[:32], "fingerprint", nil
	}
	return "line" + itoa(parseutil.SafeLine(g.StartLine)), "line", nil
}

// isRedacted is true for a placeholder in place of a credential: Gitleaks writes
// REDACTED under --redact, and Specht writes [REDACTED] into stored evidence.
// Hashing a placeholder would give every secret the same identity.
func isRedacted(secret string) bool {
	trimmed := strings.Trim(secret, "[]* ")
	return strings.EqualFold(trimmed, "redacted")
}
