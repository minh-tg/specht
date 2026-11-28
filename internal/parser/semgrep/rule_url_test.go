package semgrep_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/semgrep"
)

// The finding page links a Semgrep finding to its rule's registry page. SARIF names it in the
// rule's helpUri and --json in the result's metadata.source; both captures are one scan, so both
// formats must give each finding the same link.
func TestBothFormatsLinkTheRuleDocumentation(t *testing.T) {
	want := []string{
		"https://semgrep.dev/r/python.lang.security.audit.formatted-sql-query.formatted-sql-query",
		"https://semgrep.dev/r/python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
		"https://semgrep.dev/r/dockerfile.security.last-user-is-root.last-user-is-root",
	}
	for _, file := range []string{"semgrep-native-sarif.json", "semgrep-native.json"} {
		t.Run(file, func(t *testing.T) {
			nr := parseFile(t, file)
			require.Len(t, nr.Findings, len(want))
			for i, f := range nr.Findings {
				require.NotNil(t, f.Fix, f.Title)
				assert.Equal(t, want[i], f.Fix.URL)
				assert.Empty(t, f.Fix.Summary, "a rule page is not a fix")
			}
		})
	}
}

func TestARuleWithoutAHelpURIHasNoLink(t *testing.T) {
	data, err := os.ReadFile("../testdata/captured/semgrep.json")
	require.NoError(t, err)
	nr, err := semgrep.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, nr.Findings, 2)

	byRule := map[string]string{}
	for _, f := range nr.Findings {
		url := ""
		if f.Fix != nil {
			url = f.Fix.URL
		}
		byRule[f.Dimensions[0].Value] = url
	}
	assert.Equal(t, "https://semgrep.dev/r/go.lang.security.audit.crypto.math_random.math-random-used",
		byRule["go.lang.security.audit.crypto.math_random.math-random-used"])
	assert.Empty(t, byRule["generic.postgres-insecure-sslmode"], "the rule's helpUri is null")
}

// A report is uploaded by CI and the link ends up in an href, so only http and https survive.
func TestARuleLinkThatIsNotAWebURLIsDropped(t *testing.T) {
	for _, link := range []string{"javascript:alert(document.cookie)", "data:text/html,x", "/r/local-rule"} {
		t.Run(link, func(t *testing.T) {
			sarif := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS","rules":[` +
				`{"id":"r","helpUri":"` + link + `"}]}},"results":[{"ruleId":"r","level":"error",` +
				`"message":{"text":"m"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":3}}}]}]}]}`
			native := `{"errors":[],"paths":{"scanned":["a.py"]},"results":[{"check_id":"r","path":"a.py",` +
				`"start":{"line":3,"col":1},"extra":{"message":"m","severity":"ERROR","metadata":{"source":"` + link + `"}}}]}`
			for _, doc := range []string{sarif, native} {
				nr, err := semgrep.NewScanner().Parse(context.Background(), []byte(doc))
				require.NoError(t, err)
				require.Len(t, nr.Findings, 1)
				assert.Nil(t, nr.Findings[0].Fix)
			}
		})
	}
}
