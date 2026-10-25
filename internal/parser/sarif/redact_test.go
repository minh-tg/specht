package sarif

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/scanner"
)

func redactor(t *testing.T) scanner.Redactor {
	t.Helper()
	r, ok := any(NewScanner()).(scanner.Redactor)
	require.True(t, ok, "SARIF evidence must go through a redactor before it is stored")
	return r
}

func TestRedactRawBlanksTheSnippetOfAGitleaksSARIFReport(t *testing.T) {
	// gitleaks --report-format sarif puts the matched credential in
	// region.snippet.text.
	data, err := os.ReadFile("testdata/gitleaks.sarif")
	require.NoError(t, err)
	require.Contains(t, string(data), "placeholder-credential-value")

	out, err := redactor(t).RedactRaw(data)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "placeholder-credential-value")
	assert.Contains(t, string(out), "github-pat", "the rest of the evidence is kept")
}

func TestRedactRawBlanksContextRegions(t *testing.T) {
	doc := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r",
		"locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.go"},
		"region":{"startLine":3,"snippet":{"text":"matched-line-text"}},
		"contextRegion":{"startLine":1,"endLine":5,"snippet":{"text":"surrounding-source-text"}}}}]}]}]}`)
	out, err := redactor(t).RedactRaw(doc)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "matched-line-text")
	assert.NotContains(t, string(out), "surrounding-source-text")

	// The redacted evidence still parses to the same finding.
	before, err := NewScanner().Parse(context.Background(), doc)
	require.NoError(t, err)
	after, err := NewScanner().Parse(context.Background(), out)
	require.NoError(t, err)
	require.Len(t, after.Findings, 1)
	assert.Equal(t, before.Findings[0].Fingerprint, after.Findings[0].Fingerprint)
}

func TestRedactRawRefusesWhatItCannotRead(t *testing.T) {
	_, err := redactor(t).RedactRaw([]byte(`{"version":"2.1.0","runs":[`))
	require.ErrorIs(t, err, scanner.ErrRedactionFailed)
}
