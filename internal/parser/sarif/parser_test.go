package sarif

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/scanner"
)

func TestDescriptor_Universal(t *testing.T) {
	d := NewScanner().Descriptor()
	assert.Equal(t, "sarif", d.Name)
	assert.Equal(t, []string{"sast"}, []string{string(d.FindingKinds[0])})
	assert.False(t, d.ProvidesPackages)
	assert.True(t, d.SupportsAutoDetection)
}

func TestDetectFormat_AnySARIF(t *testing.T) {
	data, err := os.ReadFile("testdata/multi-tool.sarif.json")
	require.NoError(t, err)
	assert.True(t, NewScanner().DetectFormat(data))
	assert.False(t, NewScanner().DetectFormat([]byte(`{"version":"1.0","runs":[]}`)))
	assert.False(t, NewScanner().DetectFormat([]byte(`not json`)))
}

func TestParseMultiTool(t *testing.T) {
	data, err := os.ReadFile("testdata/multi-tool.sarif.json")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)

	// 5 results in, 2 skipped (accepted suppression + ruleless).
	require.Len(t, rep.Findings, 3)
	require.NotNil(t, rep.ScanScope)
	assert.Equal(t, "2", rep.ScanScope.Ext["skipped_results"])

	byTitle := map[string]domain.NormalizedFinding{}
	for _, f := range rep.Findings {
		byTitle[f.Title] = f
		assert.Equal(t, "sast", f.FindingKind)
	}

	semgrep := byTitle["tainted query in db.go"]
	assert.Equal(t, domain.SeverityHigh, semgrep.Severity, "result level error")
	assert.Equal(t, "db.go:42", semgrep.Location)
	assert.Contains(t, semgrep.Fingerprint, "sast:go.sql-injection:db.go:")
	assert.NotContains(t, semgrep.Fingerprint, ":42", "lines never enter identities")
	assert.Equal(t, "high", semgrep.Extensions["semgrep_precision"])
	assert.Equal(t, "db.go", dimValue(semgrep, "file"))

	xss := byTitle["xss in render"]
	assert.Equal(t, domain.SeverityHigh, xss.Severity, "security-severity 8.2")
	require.NotNil(t, xss.Fix)
	assert.Equal(t, "Escape output with encodeHTML", xss.Fix.Summary)
	assert.Equal(t, []string{"CWE-79"}, xss.Extensions["cwe"])
	assert.Equal(t, "new", xss.Extensions["baseline_state"])
	assert.NotEqual(t, semgrep.Fingerprint, xss.Fingerprint)

	locless := byTitle["config-level note without location"]
	assert.Equal(t, "(unknown)", locless.Location)
	assert.Nil(t, locless.CodeLocation)
	assert.Empty(t, dimValue(locless, "file"), "no file dim when unknown")
	assert.True(t, strings.HasPrefix(locless.Fingerprint, "sast:js/xss:(unknown)"))
}

func TestParse_StableAcrossLineShifts(t *testing.T) {
	one := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T","rules":[{"id":"r"}]}},"results":[{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":10}}}],"partialFingerprints":{"h/v1":"zzz"}}]}]}`
	two := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"T","rules":[{"id":"r"}]}},"results":[{"ruleId":"r","message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},"region":{"startLine":77}}}],"partialFingerprints":{"h/v1":"zzz"}}]}]}`
	s := NewScanner()
	a, err := s.Parse(context.Background(), []byte(one))
	require.NoError(t, err)
	b, err := s.Parse(context.Background(), []byte(two))
	require.NoError(t, err)
	require.Len(t, a.Findings, 1)
	require.Len(t, b.Findings, 1)
	assert.Equal(t, a.Findings[0].Fingerprint, b.Findings[0].Fingerprint)
}

func TestParse_Errors(t *testing.T) {
	s := NewScanner()
	_, err := s.Parse(context.Background(), []byte(`{invalid`))
	require.Error(t, err)
	_, err = s.Parse(context.Background(), []byte(`{"version":"2.0.0","runs":[]}`))
	require.ErrorIs(t, err, scanner.ErrMalformedReport)
	detail, ok := scanner.MalformedDetail(err)
	require.True(t, ok)
	assert.Equal(t, `the file declares SARIF version "2.0.0"; this reader accepts 2.1.x`, detail)
}

func dimValue(f domain.NormalizedFinding, key string) string {
	for _, d := range f.Dimensions {
		if d.Key == key {
			return d.Value
		}
	}
	return ""
}

func TestSeverity_SecuritySeverityWinsOverLevel(t *testing.T) {
	doc := func(props, defaultLevel, resultLevel string) string {
		rule := `{"id":"r"` + props
		if defaultLevel != "" {
			rule += `,"defaultConfiguration":{"level":"` + defaultLevel + `"}`
		}
		rule += `}`
		res := `{"ruleId":"r","message":{"text":"m"}`
		if resultLevel != "" {
			res += `,"level":"` + resultLevel + `"`
		}
		res += `}`
		return `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL","rules":[` + rule + `]}},"results":[` + res + `]}]}`
	}
	score := func(v string) string { return `,"properties":{"security-severity":` + v + `}` }
	cases := []struct {
		name   string
		data   string
		expect domain.Severity
	}{
		{"9.8 over error", doc(score(`"9.8"`), "error", "error"), domain.SeverityCritical},
		{"9.0 boundary", doc(score(`"9.0"`), "", "note"), domain.SeverityCritical},
		{"7.5 over warning", doc(score(`"7.5"`), "", "warning"), domain.SeverityHigh},
		{"7.0 boundary", doc(score(`7`), "", ""), domain.SeverityHigh},
		{"6.1 over error", doc(score(`"6.1"`), "error", "error"), domain.SeverityMedium},
		{"4.0 boundary", doc(score(`"4.0"`), "", ""), domain.SeverityMedium},
		{"3.9 over error", doc(score(`"3.9"`), "", "error"), domain.SeverityLow},
		{"zero falls back to result level", doc(score(`"0"`), "note", "error"), domain.SeverityHigh},
		{"out of range falls back", doc(score(`"42"`), "", "warning"), domain.SeverityMedium},
		{"non-numeric falls back", doc(score(`"high"`), "", "note"), domain.SeverityLow},
		{"no score uses result level", doc("", "note", "error"), domain.SeverityHigh},
		{"no score no result level uses default", doc("", "warning", ""), domain.SeverityMedium},
		{"nothing is unknown", doc("", "", ""), domain.SeverityUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep, err := NewScanner().Parse(context.Background(), []byte(tc.data))
			require.NoError(t, err)
			require.Len(t, rep.Findings, 1)
			assert.Equal(t, tc.expect, rep.Findings[0].Severity)
		})
	}
}

func TestSeverity_CapturedCodeQL(t *testing.T) {
	data, err := os.ReadFile("../testdata/captured/codeql.json")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	got := map[string]domain.Severity{}
	for _, f := range rep.Findings {
		got[dimValue(f, domain.DimRuleID)] = f.Severity
	}
	// Both rules default to level "error"; the score splits them.
	assert.Equal(t, domain.SeverityHigh, got["go/clear-text-logging"], "security-severity 7.5")
	assert.Equal(t, domain.SeverityMedium, got["go/log-injection"], "security-severity 6.1")
}
