package semgrep_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/semgrep"
	"github.com/minh-tg/specht/internal/scanner"
)

const semgrepSecret = "AKIATESTSECRETVALUE01"

// semgrepSecretDocs holds one report per output format. Redaction replaces the
// SARIF snippet object with the marker string, so the redacted SARIF no longer
// decodes through the parser. The parser reads the original report at ingest,
// before redaction, so the finding still ingests; only the stored copy changes.
var semgrepSecretDocs = map[string]struct {
	data     []byte
	reparses bool
}{
	"sarif":  {reparses: false, data: []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS","version":"1.100.0","rules":[{"id":"python.aws.key","shortDescription":{"text":"AWS key"},"defaultConfiguration":{"level":"error"}}]}},"results":[{"ruleId":"python.aws.key","level":"error","message":{"text":"hardcoded AWS key"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"app.py"},"region":{"startLine":3,"startColumn":1,"endLine":3,"endColumn":30,"snippet":{"text":"KEY = \"` + semgrepSecret + `\""}}}}],"fingerprints":{"matchBasedId/v1":"abc123"}}]}]}`)},
	"native": {reparses: true, data: []byte(`{"version":"1.100.0","results":[{"check_id":"python.aws.key","path":"app.py","start":{"line":3,"col":1},"end":{"line":3,"col":30},"extra":{"message":"hardcoded AWS key","severity":"ERROR","fingerprint":"fp-1","lines":"KEY = \"` + semgrepSecret + `\"","metavars":{"$KEY":{"abstract_content":"` + semgrepSecret + `"}}}}],"errors":[],"paths":{"scanned":["app.py"]}}`)},
}

func TestRedactRawRemovesTheMatchedSourceAndTheFindingStillIngests(t *testing.T) {
	for format, doc := range semgrepSecretDocs {
		t.Run(format, func(t *testing.T) {
			s := semgrep.NewScanner()
			original, err := s.Parse(context.Background(), doc.data)
			require.NoError(t, err)
			require.Len(t, original.Findings, 1)

			redacted, err := s.RedactRaw(doc.data)
			require.NoError(t, err)

			assert.NotContains(t, string(redacted), semgrepSecret)
			assert.Contains(t, string(redacted), "[REDACTED]")
			assert.Contains(t, string(redacted), "python.aws.key", "provenance survives redaction")
			if !doc.reparses {
				return
			}

			again, err := s.Parse(context.Background(), redacted)
			require.NoError(t, err, "redacted evidence still parses")
			require.Len(t, again.Findings, 1)
			assert.Equal(t, original.Findings[0].Fingerprint, again.Findings[0].Fingerprint)
			assert.Equal(t, original.Findings[0].Title, again.Findings[0].Title)
			assert.Equal(t, original.Findings[0].Severity, again.Findings[0].Severity)
		})
	}
}

// Each of these is a document the parser's decoder cannot read as one JSON
// value. The redactor must refuse them and return nothing, so the caller stores
// the failed marker instead of the input.
func TestRedactRawFailsClosedOnUndecodableInput(t *testing.T) {
	doc := semgrepSecretDocs["native"].data
	cases := map[string][]byte{
		"not json":         []byte(`not json`),
		"truncated":        doc[:len(doc)-3],
		"a second value":   append(append([]byte{}, doc...), []byte(`{}`)...),
		"trailing garbage": append(append([]byte{}, doc...), []byte(`x`)...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := semgrep.NewScanner().RedactRaw(data)

			require.ErrorIs(t, err, scanner.ErrRedactionFailed)
			assert.Empty(t, out)
		})
	}
}

// A report over the cap keeps its first RawEvidenceCap bytes in a JSON wrapper
// with the size of the raw output. The finding message is not a redacted key,
// so the size is the report's own.
func TestRedactRawCapsAReportOf200KiB(t *testing.T) {
	data := []byte(`{"version":"1.100.0","results":[{"check_id":"python.lang.rule","path":"app.py","start":{"line":1,"col":1},"extra":{"message":"` + strings.Repeat("m", 200<<10) + `","severity":"INFO","fingerprint":"fp-2"}}],"errors":[],"paths":{"scanned":["app.py"]}}`)
	require.Greater(t, len(data), 200<<10)

	out, err := semgrep.NewScanner().RedactRaw(data)
	require.NoError(t, err)

	require.True(t, json.Valid(out), "the stored value stays one JSON document")
	var stored struct {
		Truncated     bool   `json:"truncated"`
		OriginalBytes int    `json:"original_bytes"`
		Prefix        string `json:"prefix"`
	}
	require.NoError(t, json.Unmarshal(out, &stored))
	assert.True(t, stored.Truncated)
	assert.Equal(t, len(data), stored.OriginalBytes)
	assert.Len(t, stored.Prefix, scanner.RawEvidenceCap)
}

// credentialKeysAtDepth puts a credential at the root object (depth 1) and
// under four nested objects (depth 5). Each value is unique, so NotContains
// fails if any of them survives.
const credentialKeysAtDepth = `"password":"pw-depth-1","token":"tok-depth-1","api_key":"key-depth-1","nest":{"a":{"b":{"c":{"password":"pw-depth-5","token":"tok-depth-5","api_key":"key-depth-5"}}}},`

var credentialValuesAtDepth = []string{"pw-depth-1", "tok-depth-1", "key-depth-1", "pw-depth-5", "tok-depth-5", "key-depth-5"}

func TestRedactRawRedactsCredentialKeysAtDepthOneAndFive(t *testing.T) {
	for shape, doc := range semgrepSecretDocs {
		t.Run(shape, func(t *testing.T) {
			data := []byte(strings.Replace(string(doc.data), "{", "{"+credentialKeysAtDepth, 1))
			redacted, err := semgrep.NewScanner().RedactRaw(data)
			require.NoError(t, err)

			for _, v := range append(credentialValuesAtDepth, semgrepSecret) {
				assert.NotContains(t, string(redacted), v)
			}
			assert.Contains(t, string(redacted), `"api_key":"[REDACTED]"`)
		})
	}
}
