package semgrep

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/scanner"
)

func TestParseReadsEverySemgrepRun(t *testing.T) {
	raw := []byte(`{
	  "version": "2.1.0",
	  "runs": [
	    {"tool": {"driver": {"name": "Semgrep", "rules": [{"id": "rule.one"}]}},
	     "results": [{"ruleId": "rule.one", "message": {"text": "first"},
	       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "a.py"}, "region": {"startLine": 1}}}]}]},
	    {"tool": {"driver": {"name": "Semgrep", "rules": [{"id": "rule.two"}]}},
	     "results": [{"ruleId": "rule.two", "message": {"text": "second"},
	       "locations": [{"physicalLocation": {"artifactLocation": {"uri": "b.py"}, "region": {"startLine": 2}}}]}]}
	  ]
	}`)
	out, err := NewScanner().Parse(context.Background(), raw)
	require.NoError(t, err)
	require.Len(t, out.Findings, 2)
}

func TestMixedToolSARIFBelongsToTheGenericAdapter(t *testing.T) {
	raw := []byte(`{"version":"2.1.0","runs":[
	  {"tool":{"driver":{"name":"Semgrep"}},"results":[]},
	  {"tool":{"driver":{"name":"other"}},"results":[]}
	]}`)
	require.Equal(t, scanner.NotRecognized, NewScanner().Recognize(raw))
}
