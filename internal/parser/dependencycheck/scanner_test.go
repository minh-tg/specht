package dependencycheck_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/parser/dependencycheck"
	"github.com/xMinhx/specht/internal/scanner"
)

func TestName(t *testing.T) {
	s := dependencycheck.NewScanner()
	assert.Equal(t, "dependency-check", s.Name())
}

func TestDetect_ValidInput(t *testing.T) {
	s := dependencycheck.NewScanner()
	data, err := os.ReadFile("testdata/dependency-check-report.json")
	require.NoError(t, err)
	assert.True(t, s.DetectFormat(data))
}

func TestDetect_InvalidInput(t *testing.T) {
	s := dependencycheck.NewScanner()
	assert.False(t, s.DetectFormat([]byte(`{}`)))
	assert.False(t, s.DetectFormat([]byte(`not json`)))
}

func TestParse_DependencyCheckReport(t *testing.T) {
	s := dependencycheck.NewScanner()
	data, err := os.ReadFile("testdata/dependency-check-report.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	assert.Equal(t, "dependency-check", report.ToolName)
	require.NotNil(t, report.Target)
	assert.Len(t, report.Findings, 2)

	tests := []struct {
		name        string
		fingerprint string
		severity    scanner.Severity
		score       float64
		findingKind string
		cvssVersion string
	}{
		{
			name:        "first finding should be CVE-2021-44228",
			fingerprint: "CVE-2021-44228:pkg:maven/org.apache.logging.log4j/log4j-core@2.17.0",
			severity:    scanner.SeverityCritical,
			score:       10.0,
			findingKind: "sca",
			cvssVersion: "3.1",
		},
		{
			name:        "second finding should be CVE-2020-25649",
			fingerprint: "CVE-2020-25649:pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8",
			severity:    scanner.SeverityHigh,
			score:       7.5,
			findingKind: "sca",
			cvssVersion: "3.1",
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
					if tt.cvssVersion != "" {
						require.NotNil(t, f.CVSS)
						assert.Equal(t, tt.cvssVersion, f.CVSS.Version)
					}
					break
				}
			}
			assert.True(t, found, "finding with fingerprint %q not found", tt.fingerprint)
		})
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	s := dependencycheck.NewScanner()
	_, err := s.Parse(context.Background(), []byte(`not json`))
	assert.Error(t, err)
}

func TestFindingKind(t *testing.T) {
	s := dependencycheck.NewScanner()
	assert.Equal(t, "sca", s.FindingKind())
}
