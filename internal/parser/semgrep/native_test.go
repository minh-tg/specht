package semgrep_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/semgrep"
	"github.com/minh-tg/specht/internal/scanner"
)

func parseFile(t *testing.T, name string) *domain.NormalizedReport {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	nr, err := semgrep.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	return nr
}

// TestNativeAndSARIFAgree holds the two output formats of one Semgrep scan to the same findings.
// A project that moves from --sarif to --json, or the other way, must keep its finding history, so
// identity, title, severity and location have to match exactly. The description is left out on
// purpose: SARIF carries the rule's template text (with placeholders such as $FUNC) while --json
// only has the message for the finding, so the native description is the more useful one.
func TestNativeAndSARIFAgree(t *testing.T) {
	native := parseFile(t, "semgrep-native.json")
	sarif := parseFile(t, "semgrep-native-sarif.json")

	require.Len(t, native.Findings, 3)
	require.Len(t, sarif.Findings, len(native.Findings))
	for i, n := range native.Findings {
		s := sarif.Findings[i]
		assert.Equal(t, s.Fingerprint, n.Fingerprint, "same identity")
		assert.Equal(t, s.FindingKind, n.FindingKind)
		assert.Equal(t, s.Title, n.Title)
		assert.Equal(t, s.Severity, n.Severity)
		assert.Equal(t, s.Location, n.Location)
		assert.Equal(t, s.Dimensions, n.Dimensions)
	}
	assert.Equal(t, sarif.ScanType, native.ScanType)
	for _, n := range native.Findings {
		assert.Equal(t, n.Title, n.Description, "the native description is the finding's own message")
	}
}

func TestNativeFindingFields(t *testing.T) {
	nr := parseFile(t, "semgrep-native.json")
	require.Len(t, nr.Findings, 3)

	sql := nr.Findings[0]
	assert.Regexp(t, `^sast:python\.lang\.security\.audit\.formatted-sql-query\.formatted-sql-query:app\.py:t[0-9a-f]{12}$`, sql.Fingerprint,
		"rule, file and a digest of the message; the line is not part of it")
	assert.Equal(t, "sast", sql.FindingKind)
	assert.Equal(t, "app.py:4", sql.Location)
	assert.Equal(t, domain.SeverityMedium, sql.Severity, "WARNING is medium")
	assert.Equal(t, "Detected possible formatted SQL query. Use parameterized queries instead.", sql.Title)
	assert.Equal(t, domain.SeverityHigh, nr.Findings[1].Severity, "ERROR is high")

	assert.Equal(t, "security", sql.Extensions["category"])
	assert.Equal(t, "WARNING", sql.Extensions["semgrep_severity"])
	assert.NotEmpty(t, sql.Extensions["cwe"], "the CWE the rule names is kept")
	assert.NotEmpty(t, sql.Extensions["owasp"])
}

func TestNativeSeverities(t *testing.T) {
	for level, want := range map[string]domain.Severity{
		"ERROR": domain.SeverityHigh, "WARNING": domain.SeverityMedium, "INFO": domain.SeverityLow,
		"INVENTORY": domain.SeverityUnknown, "EXPERIMENT": domain.SeverityUnknown, "": domain.SeverityUnknown,
	} {
		t.Run(level, func(t *testing.T) {
			doc := `{"version":"1.0","paths":{},"errors":[],"results":[{"check_id":"a.b","path":"x.py",` +
				`"start":{"line":3},"end":{"line":3},"extra":{"message":"m","severity":"` + level + `"}}]}`
			nr, err := semgrep.NewScanner().Parse(context.Background(), []byte(doc))
			require.NoError(t, err)
			require.Len(t, nr.Findings, 1)
			assert.Equal(t, want, nr.Findings[0].Severity)
		})
	}
}

func TestNativeCleanReport(t *testing.T) {
	doc := `{"version":"1.172.0","results":[],"errors":[],"paths":{"scanned":["app.py"]}}`
	s := semgrep.NewScanner()
	assert.Equal(t, scanner.Definite, s.Recognize([]byte(doc)), "a clean Semgrep report names itself by its shape")
	nr, err := s.Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	assert.Empty(t, nr.Findings)
	assert.Equal(t, domain.ScanTypeFilesystem, nr.ScanType)
}

func TestNativeRecordsScanErrors(t *testing.T) {
	doc := `{"version":"1.0","results":[],"paths":{},"errors":[{"type":"SyntaxError","path":"bad.py"},{"type":"Timeout","path":"big.py"}]}`
	nr, err := semgrep.NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	require.NotNil(t, nr.ScanScope)
	assert.Equal(t, "2", nr.ScanScope.Ext["semgrep_errors"], "files Semgrep could not scan are noted on the report")
}

func TestNativeRecognition(t *testing.T) {
	s := semgrep.NewScanner()
	for name, tc := range map[string]struct {
		doc  string
		want scanner.Recognition
	}{
		"results with check ids":     {`{"results":[{"check_id":"a.b","path":"x"}]}`, scanner.Definite},
		"a clean report":             {`{"version":"1","results":[],"errors":[],"paths":{}}`, scanner.Definite},
		"results without check ids":  {`{"results":[{"test_id":"B101"}]}`, scanner.NotRecognized},
		"an empty results list only": {`{"results":[]}`, scanner.NotRecognized},
		"bandit":                     {`{"errors":[],"generated_at":"x","metrics":{},"results":[]}`, scanner.NotRecognized},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, s.Recognize([]byte(tc.doc)))
		})
	}
}

func TestNativeMalformed(t *testing.T) {
	_, err := semgrep.NewScanner().Parse(context.Background(),
		[]byte(`{"version":"1","paths":{},"errors":[],"results":[{"check_id":"a","path":"x","start":"oops"}]}`))
	require.ErrorIs(t, err, scanner.ErrMalformedReport)
}
