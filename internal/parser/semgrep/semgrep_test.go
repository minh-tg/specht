package semgrep_test

import (
	"context"
	"os"
	"testing"

	"github.com/minh-tg/specht/internal/domain"

	"github.com/minh-tg/specht/internal/parser/semgrep"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestName(t *testing.T) {
	s := semgrep.NewScanner()
	assert.Equal(t, "semgrep", s.Descriptor().Name)
}

func TestDetect_ValidInput(t *testing.T) {
	s := semgrep.NewScanner()
	data, err := os.ReadFile("testdata/semgrep-sarif.json")
	require.NoError(t, err)
	assert.True(t, s.DetectFormat(data))
}

func TestDetect_InvalidInput(t *testing.T) {
	s := semgrep.NewScanner()
	assert.False(t, s.DetectFormat([]byte(`{}`)))
	assert.False(t, s.DetectFormat([]byte(`{"runs":[]}`)))
	assert.False(t, s.DetectFormat([]byte(`not json`)))
}

func TestParse_SemgrepScan(t *testing.T) {
	s := semgrep.NewScanner()
	data, err := os.ReadFile("testdata/semgrep-sarif.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	require.Len(t, report.Findings, 2)

	tests := []struct {
		name        string
		fingerprint string
		severity    domain.Severity
		findingKind string
		location    string
		ruleID      string
		cwe         any
	}{
		{
			name:        "first finding is JWT hardcoded secret",
			fingerprint: "sast:go.jwt-hardcoded-secret:src/auth/login.go:42",
			severity:    domain.SeverityHigh,
			findingKind: "sast",
			location:    "src/auth/login.go:42",
			ruleID:      "go.jwt-hardcoded-secret",
			cwe:         []any{"CWE-798"},
		},
		{
			name:        "second finding is Flask debug enabled",
			fingerprint: "sast:python.flask.debug-enabled:src/app.py:15",
			severity:    domain.SeverityMedium,
			findingKind: "sast",
			location:    "src/app.py:15",
			ruleID:      "python.flask.debug-enabled",
			cwe:         []any{"CWE-489"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := findByFingerprint(t, report.Findings, tt.fingerprint)
			assert.Equal(t, tt.findingKind, f.FindingKind)
			assert.Equal(t, tt.severity, f.Severity)
			assert.Equal(t, tt.location, f.Location)
			assert.Equal(t, tt.ruleID, dimensionValue(f.Dimensions, "rule_id"))

			if tt.cwe != nil {
				assert.Equal(t, tt.cwe, f.Extensions["cwe"])
			}
		})
	}
}

// findByFingerprint returns the matching finding or fails the test.
func findByFingerprint(t *testing.T, findings []domain.NormalizedFinding, fingerprint string) domain.NormalizedFinding {
	t.Helper()
	for _, f := range findings {
		if f.Fingerprint == fingerprint {
			return f
		}
	}
	t.Fatalf("finding with fingerprint %q not found", fingerprint)
	return domain.NormalizedFinding{}
}

// dimensionValue returns the value of the named dimension, or "".
func dimensionValue(dims []domain.Dimension, key string) string {
	for _, d := range dims {
		if d.Key == key {
			return d.Value
		}
	}
	return ""
}

func TestParse_InvalidJSON(t *testing.T) {
	s := semgrep.NewScanner()
	_, err := s.Parse(context.Background(), []byte(`not json`))
	assert.Error(t, err)
}

func TestParse_EmptyReport(t *testing.T) {
	s := semgrep.NewScanner()
	data := []byte(`{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": [
			{
				"tool": { "driver": { "name": "semgrep", "version": "1.0.0" } },
				"results": [],
				"artifacts": [],
				"columnKind": "utf16CodeUnits",
				"originalUriBaseIds": { "%SRCROOT%": { "uri": "file:///" } }
			}
		]
	}`)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)
	assert.Empty(t, report.Findings)
}

func TestFindingKind(t *testing.T) {
	s := semgrep.NewScanner()
	assert.Equal(t, "sast", string(s.Descriptor().FindingKinds[0]))
}
