package grype_test

import (
	"context"
	"os"
	"testing"

	"github.com/minh-tg/specht/internal/domain"

	"github.com/minh-tg/specht/internal/parser/grype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestName(t *testing.T) {
	s := grype.NewScanner()
	assert.Equal(t, "grype", s.Descriptor().Name)
}

func TestDetect_ValidInput(t *testing.T) {
	s := grype.NewScanner()
	data, err := os.ReadFile("testdata/grype-report.json")
	require.NoError(t, err)
	assert.True(t, s.DetectFormat(data))
}

func TestDetect_InvalidInput(t *testing.T) {
	s := grype.NewScanner()
	assert.False(t, s.DetectFormat([]byte(`{}`)))
	assert.False(t, s.DetectFormat([]byte(`not json`)))
}

func TestParse_GrypeReport(t *testing.T) {
	s := grype.NewScanner()
	data, err := os.ReadFile("testdata/grype-report.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	require.NotNil(t, report.Target)
	assert.Len(t, report.Findings, 2)

	tests := []struct {
		name        string
		fingerprint string
		severity    domain.Severity
		score       float64
		findingKind string
		cvssVersion string
		aliasesLen  int
		fixSummary  string
	}{
		{
			name:        "first finding should be CVE-2023-25165",
			fingerprint: "CVE-2023-25165:pkg:golang/helm.sh/helm/v3@v3.11.1",
			severity:    domain.SeverityHigh,
			score:       9.8,
			findingKind: "sca",
			cvssVersion: "3.1",
			aliasesLen:  1,
			fixSummary:  "v3.11.3, v3.10.3",
		},
		{
			name:        "second finding should be GHSA-c3h9-896r-86jm",
			fingerprint: "GHSA-c3h9-896r-86jm:pkg:golang/github.com/gogo/protobuf@v1.3.1",
			severity:    domain.SeverityCritical,
			score:       9.8,
			findingKind: "sca",
			cvssVersion: "3.1",
			aliasesLen:  1,
			fixSummary:  "v1.3.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := grypeFindingByFingerprint(t, report.Findings, tt.fingerprint)
			assert.Equal(t, tt.severity, f.Severity)
			assert.Equal(t, tt.findingKind, f.FindingKind)
			assert.Equal(t, tt.score, f.Score)
			assert.Len(t, f.Aliases, tt.aliasesLen)
			if tt.cvssVersion != "" {
				require.NotNil(t, f.CVSS)
				assert.Equal(t, tt.cvssVersion, f.CVSS.Version)
			}
			if tt.fixSummary != "" {
				require.NotNil(t, f.Fix)
				assert.Equal(t, tt.fixSummary, f.Fix.Summary)
			}
		})
	}
}

// grypeFindingByFingerprint returns the matching finding or fails the test.
func grypeFindingByFingerprint(t *testing.T, findings []domain.NormalizedFinding, fingerprint string) domain.NormalizedFinding {
	t.Helper()
	for _, f := range findings {
		if f.Fingerprint == fingerprint {
			return f
		}
	}
	t.Fatalf("finding with fingerprint %q not found", fingerprint)
	return domain.NormalizedFinding{}
}

func TestParse_GrypeFullReport(t *testing.T) {
	s := grype.NewScanner()
	data, err := os.ReadFile("testdata/grype-full.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	// Grype's standard JSON only reports matched (vulnerable) artifacts, so
	// findings and inventory are the same population here. Every matched
	// artifact is captured, deduplicated by normalized purl.
	require.Len(t, report.Findings, 105)
	require.GreaterOrEqual(t, len(report.Packages), 100)
	require.Equal(t, len(report.Packages), len(report.Findings))

	seen := map[string]bool{}
	lodashSeen := false
	for _, p := range report.Packages {
		assert.NotContains(t, p.PURL, "?")
		assert.NotContains(t, p.PURL, "#")
		assert.False(t, seen[p.PURL], "duplicate inventory purl %s", p.PURL)
		seen[p.PURL] = true
		assert.Equal(t, "npm", p.Ecosystem)
		assert.Equal(t, "/app/package-lock.json", p.ManifestPath)
		if p.Name == "lodash" {
			lodashSeen = true
			assert.Contains(t, p.PURL, "pkg:npm/lodash@")
			assert.NotEmpty(t, p.Version)
		}
	}
	assert.True(t, lodashSeen, "lodash missing from inventory")
}

func TestParse_InvalidJSON(t *testing.T) {
	s := grype.NewScanner()
	_, err := s.Parse(context.Background(), []byte(`not json`))
	assert.Error(t, err)
}

func TestFindingKind(t *testing.T) {
	s := grype.NewScanner()
	assert.Equal(t, "sca", string(s.Descriptor().FindingKinds[0]))
}

func TestParse_GrypeReport_Aliases(t *testing.T) {
	s := grype.NewScanner()
	data, err := os.ReadFile("testdata/grype-report.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, report.Findings, 2)

	ghsaFinding := report.Findings[1]
	assert.Equal(t, "ghsa", ghsaFinding.Extensions["namespace"])
	assert.Equal(t, "CVE-2021-3121", ghsaFinding.Aliases[0])
}
