package parser_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/parser/parseutil"
)

// TestBuiltinsAdversarialPayloads tests every registered scanner adapter against
// intentionally hostile inputs: null byte injections, path traversal climbing,
// oversized inputs (1MB+ fields), deeply nested structures, and malformed types.
// In all cases, adapters must NOT panic, and any findings/packages emitted
// must satisfy hardening invariants (no null bytes, bounded lengths, safe lines).
func TestBuiltinsAdversarialPayloads(t *testing.T) {
	builtins := parser.Builtins()

	hugeString := strings.Repeat("A", 100*1024) // 100KB string
	traversalPath := "../../../../../../../../etc/passwd"
	nullBytePayload := "malicious\x00data%00test"

	type testCase struct {
		name    string
		payload string
	}

	adversarialCases := []testCase{
		{
			name:    "empty input",
			payload: "",
		},
		{
			name:    "whitespace only",
			payload: "   \t\r\n   ",
		},
		{
			name:    "null bytes only",
			payload: "\x00\x00\x00\x00",
		},
		{
			name:    "truncated JSON object",
			payload: `{"runs": [{"tool": {`,
		},
		{
			name:    "truncated JSON array",
			payload: `[{"template-id": "x", `,
		},
		{
			name:    "deeply nested JSON",
			payload: strings.Repeat(`{"nest":`, 200) + `{"val": 1}` + strings.Repeat(`}`, 200),
		},
		{
			name: "oversized fields and path traversal in generic JSON",
			payload: `{
				"runs": [{
					"tool": {"driver": {"name": "malicious-scanner"}},
					"results": [{
						"ruleId": "` + hugeString + `",
						"message": {"text": "` + nullBytePayload + hugeString + `"},
						"locations": [{
							"physicalLocation": {
								"artifactLocation": {"uri": "` + traversalPath + `\x00secret"},
								"region": {"startLine": -9999, "endLine": -10}
							}
						}]
					}]
				}]
			}`,
		},
		{
			name: "trivy adversarial JSON",
			payload: `{
				"SchemaVersion": 2,
				"ArtifactName": "` + traversalPath + `",
				"Results": [{
					"Target": "` + traversalPath + `\x00inject",
					"Class": "os-pkgs",
					"Type": "alpine",
					"Vulnerabilities": [{
						"VulnerabilityID": "CVE-2024-9999\x00",
						"PkgName": "` + hugeString + `",
						"InstalledVersion": "1.0.0",
						"Title": "` + hugeString + `",
						"Description": "` + nullBytePayload + hugeString + `",
						"Severity": "CRITICAL"
					}],
					"Secrets": [{
						"RuleID": "` + hugeString + `",
						"Title": "` + nullBytePayload + `"
					}],
					"Misconfigurations": [{
						"RuleID": "` + hugeString + `",
						"Title": "` + nullBytePayload + `"
					}]
				}]
			}`,
		},
		{
			name: "nuclei adversarial JSONL",
			payload: `{"template-id": "` + hugeString + `", "host": "` + traversalPath + `\x00test", "matched-at": "http://example.com/` + traversalPath + `?x=` + hugeString + `", "info": {"name": "` + nullBytePayload + `", "severity": "critical"}}` + "\n" +
				`{"template-id": "normal-id", "host": "http://clean.com", "info": {"severity": "high"}}` + "\n",
		},
		{
			name: "sbom cyclonedx adversarial",
			payload: `{
				"bomFormat": "CycloneDX",
				"serialNumber": "` + hugeString + `",
				"metadata": {
					"component": {"name": "` + hugeString + `", "version": "1.0.0"}
				},
				"components": [{
					"type": "library",
					"name": "` + nullBytePayload + hugeString + `",
					"version": "` + hugeString + `",
					"purl": "pkg:npm/` + hugeString + `@1.0.0\x00injection"
				}]
			}`,
		},
		{
			name: "checkov adversarial JSON",
			payload: `{
				"check_type": "terraform",
				"results": {
					"failed_checks": [{
						"check_id": "` + hugeString + `",
						"check_name": "` + nullBytePayload + `",
						"file_path": "` + traversalPath + `",
						"file_line_range": [-500, -100]
					}]
				}
			}`,
		},
		{
			name: "dependency-check adversarial",
			payload: `{
				"reportSchema": "1.1",
				"dependencies": [{
					"fileName": "` + hugeString + `",
					"filePath": "` + traversalPath + `",
					"packages": [{"id": "pkg:maven/` + hugeString + `@1.0"}],
					"vulnerabilities": [{
						"name": "` + hugeString + `",
						"description": "` + nullBytePayload + `",
						"severity": "CRITICAL",
						"cvssv3": {"baseScore": 999.9}
					}]
				}]
			}`,
		},
	}

	for _, sc := range builtins {
		scannerName := sc.Descriptor().Name
		t.Run(scannerName, func(t *testing.T) {
			for _, tc := range adversarialCases {
				t.Run(tc.name, func(t *testing.T) {
					// The primary invariant: Parse MUST NEVER panic
					assert.NotPanics(t, func() {
						rep, err := sc.Parse(context.Background(), []byte(tc.payload))
						if err != nil {
							// Clean parse failure is entirely expected for adversarial payloads
							return
						}
						if rep == nil {
							return
						}

						// If the parser succeeded in returning a report, all findings and
						// packages MUST obey domain hardening rules
						for _, f := range rep.Findings {
							assert.NotContains(t, f.Fingerprint, "\x00", "fingerprint must not contain null bytes")
							assert.LessOrEqual(t, len(f.Fingerprint), parseutil.MaxFingerprintLength, "fingerprint exceeds limit")

							assert.NotContains(t, f.Title, "\x00", "title must not contain null bytes")
							assert.LessOrEqual(t, len(f.Title), parseutil.MaxTitleLength, "title exceeds limit")

							assert.NotContains(t, f.Description, "\x00", "description must not contain null bytes")
							assert.LessOrEqual(t, len(f.Description), parseutil.MaxDescriptionLength, "description exceeds limit")

							assert.NotContains(t, f.Location, "\x00", "location must not contain null bytes")
							assert.LessOrEqual(t, len(f.Location), parseutil.MaxPathLength, "location exceeds limit")

							if f.CodeLocation != nil {
								assert.NotContains(t, f.CodeLocation.File, "\x00")
								assert.GreaterOrEqual(t, f.CodeLocation.StartLine, 0, "start line cannot be negative")
								assert.GreaterOrEqual(t, f.CodeLocation.EndLine, 0, "end line cannot be negative")
								assert.False(t, strings.HasPrefix(f.CodeLocation.File, "../"), "file location must not escape root")
							}

							for _, d := range f.Dimensions {
								assert.NotContains(t, d.Value, "\x00", "dimension value must not contain null bytes")
								assert.LessOrEqual(t, len(d.Value), parseutil.MaxDimensionValueLength, "dimension value exceeds limit")
							}

							assert.GreaterOrEqual(t, f.Score, 0.0, "score cannot be negative")
							assert.LessOrEqual(t, f.Score, 10.0, "score cannot exceed 10.0")
						}

						for _, p := range rep.Packages {
							assert.NotContains(t, p.PURL, "\x00")
							assert.NotContains(t, p.Name, "\x00")
							assert.NotContains(t, p.Version, "\x00")
							assert.NotContains(t, p.ManifestPath, "\x00")
							assert.False(t, strings.HasPrefix(p.ManifestPath, "../"), "manifest path must not escape root")
						}
					})
				})
			}
		})
	}
}
