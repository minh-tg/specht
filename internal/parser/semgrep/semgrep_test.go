package semgrep_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/parser/semgrep"
	"github.com/xMinhx/specht/internal/scanner"
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
		severity    scanner.Severity
		findingKind string
		location    string
		ruleID      string
		cwe         any
	}{
		{
			name:        "first finding is JWT hardcoded secret",
			fingerprint: "sast:go.jwt-hardcoded-secret:src/auth/login.go:42",
			severity:    scanner.SeverityHigh,
			findingKind: "sast",
			location:    "src/auth/login.go:42",
			ruleID:      "go.jwt-hardcoded-secret",
			cwe:         []any{"CWE-798"},
		},
		{
			name:        "second finding is Flask debug enabled",
			fingerprint: "sast:python.flask.debug-enabled:src/app.py:15",
			severity:    scanner.SeverityMedium,
			findingKind: "sast",
			location:    "src/app.py:15",
			ruleID:      "python.flask.debug-enabled",
			cwe:         []any{"CWE-489"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := false
			for _, f := range report.Findings {
				if f.Fingerprint == tt.fingerprint {
					found = true
					assert.Equal(t, tt.findingKind, f.FindingKind)
					assert.Equal(t, tt.severity, f.Severity)
					assert.Equal(t, tt.location, f.Location)

					hasRuleID := false
					for _, d := range f.Dimensions {
						if d.Key == "rule_id" && d.Value == tt.ruleID {
							hasRuleID = true
						}
					}
					assert.True(t, hasRuleID, "finding missing rule_id dimension")

					if tt.cwe != nil {
						assert.Equal(t, tt.cwe, f.Extensions["cwe"])
					}
					break
				}
			}
			assert.True(t, found, "finding with fingerprint %q not found", tt.fingerprint)
		})
	}
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
