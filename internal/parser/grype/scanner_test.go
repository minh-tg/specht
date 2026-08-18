package grype_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/parser/grype"
	"github.com/xMinhx/specht/internal/scanner"
)

func TestName(t *testing.T) {
	s := grype.NewScanner()
	assert.Equal(t, "grype", s.Name())
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

	assert.Equal(t, "grype", report.ToolName)
	require.NotNil(t, report.Target)
	assert.Len(t, report.Findings, 2)

	tests := []struct {
		name        string
		fingerprint string
		severity    scanner.Severity
		score       float64
		findingKind string
		cvssVersion string
		aliasesLen  int
		fixSummary  string
	}{
		{
			name:        "first finding should be CVE-2023-25165",
			fingerprint: "CVE-2023-25165:pkg:golang/helm.sh/helm/v3@v3.11.1",
			severity:    scanner.SeverityHigh,
			score:       9.8,
			findingKind: "sca",
			cvssVersion: "3.1",
			aliasesLen:  1,
			fixSummary:  "v3.11.3, v3.10.3",
		},
		{
			name:        "second finding should be GHSA-c3h9-896r-86jm",
			fingerprint: "GHSA-c3h9-896r-86jm:pkg:golang/github.com/gogo/protobuf@v1.3.1",
			severity:    scanner.SeverityCritical,
			score:       9.8,
			findingKind: "sca",
			cvssVersion: "3.1",
			aliasesLen:  1,
			fixSummary:  "v1.3.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := false
			for _, f := range report.Findings {
				if f.Fingerprint == tt.fingerprint {
					found = true
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
					break
				}
			}
			assert.True(t, found, "finding with fingerprint %q not found", tt.fingerprint)
		})
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	s := grype.NewScanner()
	_, err := s.Parse(context.Background(), []byte(`not json`))
	assert.Error(t, err)
}

func TestFindingKind(t *testing.T) {
	s := grype.NewScanner()
	assert.Equal(t, "sca", s.FindingKind())
}

func TestParse_GrypeReport_Aliases(t *testing.T) {
	s := grype.NewScanner()
	data, err := os.ReadFile("testdata/grype-report.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, report.Findings, 2)

	ghsaFinding := report.Findings[1]
	assert.Equal(t, "GHSA-c3h9-896r-86jm", ghsaFinding.Metadata["vulnerability_id"])
	assert.Len(t, ghsaFinding.Aliases, 1)
	assert.Equal(t, "CVE-2021-3121", ghsaFinding.Aliases[0])
}
