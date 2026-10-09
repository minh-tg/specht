package parser_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/scanner"
)

func TestCapturedReports(t *testing.T) {
	byName := map[string]scanner.Scanner{}
	for _, s := range parser.Builtins() {
		byName[s.Descriptor().Name] = s
	}
	cases := []struct {
		file     string
		scanner  string
		findings int
		packages int
	}{
		{"trivy.json", "trivy", 12, 0},
		{"osv-scanner.json", "osv-scanner", 2, 1},
		{"grype.json", "grype", 2, 1},
		{"dependency-check.json", "dependency-check", 4, 2},
		{"checkov.json", "checkov", 3, 0},
		{"tfsec.json", "tfsec", 3, 0},
		{"nuclei.json", "nuclei", 1, 0},
		{"gitleaks.json", "gitleaks", 1, 0},
		{"semgrep.json", "semgrep", 2, 0},
		{"codeql.json", "sarif", 2, 0},
		{"cyclonedx.json", "sbom", 0, 3},
		{"spdx.json", "sbom", 0, 3},
	}
	for _, tc := range cases {
		t.Run(tc.file, func(t *testing.T) {
			data, err := os.ReadFile(filepath.Join("testdata", "captured", tc.file))
			require.NoError(t, err)
			s := byName[tc.scanner]
			require.NotNil(t, s)
			assert.True(t, s.DetectFormat(data), "native output must be recognizable")
			report, err := s.Parse(context.Background(), data)
			require.NoError(t, err)
			require.Len(t, report.Findings, tc.findings)
			assert.Len(t, report.Packages, tc.packages)

			seen := map[string]bool{}
			for _, f := range report.Findings {
				require.NotEmpty(t, f.Fingerprint)
				assert.False(t, seen[f.Fingerprint], "different captured checks must remain distinct")
				seen[f.Fingerprint] = true
				assert.GreaterOrEqual(t, f.Severity, domain.SeverityUnknown)
				assert.LessOrEqual(t, f.Severity, domain.SeverityCritical)
				for _, d := range f.Dimensions {
					assert.NotEmpty(t, d.Value)
					assert.Contains(t, canonicalDims, d.Key)
				}
			}
			if tc.scanner == "osv-scanner" {
				for _, f := range report.Findings {
					assert.Contains(t, f.Fingerprint, ":pkg:npm/lodash")
					require.NotNil(t, f.Fix)
					assert.Equal(t, "4.17.21", f.Fix.Summary)
				}
				assert.Equal(t, domain.SeverityMedium, report.Findings[0].Severity, "OSV MODERATE means medium")
				assert.Equal(t, domain.SeverityHigh, report.Findings[1].Severity)
			}
			if tc.scanner == "tfsec" {
				for _, f := range report.Findings {
					assert.Equal(t, "iac", f.FindingKind)
					assert.Equal(t, domain.SeverityHigh, f.Severity)
				}
			}
		})
	}
}

func TestCapturedReportProvenance(t *testing.T) {
	var manifest struct {
		Fixtures []struct {
			File            string   `json:"file"`
			Scanner         string   `json:"scanner"`
			ToolVersion     string   `json:"tool_version"`
			SourceSHA256    string   `json:"source_sha256"`
			FixtureSHA256   string   `json:"fixture_sha256"`
			Transformations []string `json:"transformations"`
		} `json:"fixtures"`
	}
	data, err := os.ReadFile("testdata/captured/manifest.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &manifest))
	require.Len(t, manifest.Fixtures, 12)
	seen := map[string]bool{}
	for _, f := range manifest.Fixtures {
		t.Run(f.File, func(t *testing.T) {
			require.False(t, seen[f.File], "duplicate fixture entry")
			seen[f.File] = true
			assert.NotEmpty(t, f.Scanner)
			assert.NotEmpty(t, f.ToolVersion)
			assert.NotEmpty(t, f.Transformations)
			sourceHash, err := hex.DecodeString(f.SourceSHA256)
			require.NoError(t, err)
			assert.Len(t, sourceHash, sha256.Size)
			raw, err := os.ReadFile(filepath.Join("testdata", "captured", f.File))
			require.NoError(t, err)
			sum := sha256.Sum256(raw)
			assert.Equal(t, f.FixtureSHA256, hex.EncodeToString(sum[:]))
		})
	}
	files, err := filepath.Glob("testdata/captured/*.json")
	require.NoError(t, err)
	assert.Len(t, files, len(manifest.Fixtures)+1, "every report must have a provenance entry")
}
