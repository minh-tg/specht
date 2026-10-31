package sarif

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Producers that were given an absolute target write it into artifactLocation.uri,
// either as a plain path (Semgrep, Bandit) or as a file: URI (Gosec, CodeQL
// databases built outside the Actions runner). The checkout directory differs per
// runner and must not be part of a finding's identity.
func absoluteURILog(uri string) string {
	return fmt.Sprintf(`{
  "version": "2.1.0",
  "runs": [{
    "tool": {"driver": {"name": "gosec", "rules": [{"id": "G201", "shortDescription": {"text": "SQL string formatting"}}]}},
    "results": [{
      "ruleId": "G201",
      "level": "error",
      "message": {"text": "SQL string formatting"},
      "locations": [{"physicalLocation": {
        "artifactLocation": {"uri": %q},
        "region": {"startLine": 42}
      }}],
      "partialFingerprints": {"primaryLocationLineHash": "ab12cd34"}
    }]
  }]
}`, uri)
}

func TestAFindingKeepsItsIdentityFromAnotherCheckout(t *testing.T) {
	parse := func(uri string) (fingerprint, file string) {
		rep, err := NewScanner().Parse(context.Background(), []byte(absoluteURILog(uri)))
		require.NoError(t, err)
		require.Len(t, rep.Findings, 1)
		f := rep.Findings[0]
		return f.Fingerprint, f.CodeLocation.File
	}
	want, wantFile := parse("internal/db/query.go")
	assert.Equal(t, "internal/db/query.go", wantFile)

	for _, uri := range []string{
		"/src/internal/db/query.go",
		"/github/workspace/internal/db/query.go",
		"/builds/x/1/internal/db/query.go",
		"/home/runner/work/api/api/internal/db/query.go",
		"file:///src/internal/db/query.go",
		"file:///home/runner/work/api/api/internal/db/query.go",
		"file:///builds/acme/api/internal/db/query.go",
	} {
		got, gotFile := parse(uri)
		assert.Equal(t, want, got, uri)
		assert.Equal(t, wantFile, gotFile, uri)
	}
}

func TestTheIdentityFormulaIsVersioned(t *testing.T) {
	assert.EqualValues(t, 2, NewScanner().Descriptor().FingerprintVersion)
	rep, err := NewScanner().Parse(context.Background(), []byte(absoluteURILog("a.go")))
	require.NoError(t, err)
	assert.EqualValues(t, 2, rep.FingerprintVersion)
}
