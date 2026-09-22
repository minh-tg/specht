package sarif

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
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
	require.ErrorContains(t, err, "unsupported version")
}

func dimValue(f domain.NormalizedFinding, key string) string {
	for _, d := range f.Dimensions {
		if d.Key == key {
			return d.Value
		}
	}
	return ""
}
