package nuclei

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/scanner"
)

func TestDescriptor_DAST(t *testing.T) {
	d := NewScanner().Descriptor()
	assert.Equal(t, "nuclei", d.Name)
	assert.Equal(t, []string{"dast"}, []string{string(d.FindingKinds[0])})
	assert.Contains(t, d.ScanTypes, domain.ScanTypeDAST)
}

func TestDetectFormat_JSONL(t *testing.T) {
	data, err := os.ReadFile("testdata/nuclei.jsonl")
	require.NoError(t, err)
	assert.True(t, NewScanner().DetectFormat(data))
	assert.False(t, NewScanner().DetectFormat([]byte(`[{"Target":"x"}]`)))
}

func TestParseQueryStrippedIdentity(t *testing.T) {
	data, err := os.ReadFile("testdata/nuclei.jsonl")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 3)
	assert.Equal(t, domain.ScanTypeDAST, rep.ScanType)

	headers := rep.Findings[0]
	assert.Equal(t, "dast:http-missing-security-headers:https://app.example.com/dashboard", headers.Fingerprint)
	assert.Equal(t, domain.SeverityMedium, headers.Severity)

	// Same template, same path, different query strings: identical identity,
	// distinct parameter dims.
	first := rep.Findings[1]
	second := rep.Findings[2]
	assert.Equal(t, first.Fingerprint, second.Fingerprint)
	assert.Equal(t, domain.SeverityCritical, first.Severity)
	assert.Equal(t, "https://api.example.com/search", dimValue(first, "url"))
	assert.ElementsMatch(t, []string{"q", "lang"}, paramValues(first))
	assert.ElementsMatch(t, []string{"q", "page"}, paramValues(second))
	assert.Equal(t, "CVE-2024-1111", dimValue(first, "rule_id"))
}

func TestParseRedactsBodies(t *testing.T) {
	data, err := os.ReadFile("testdata/nuclei.jsonl")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	marshaled, err := json.Marshal(rep)
	require.NoError(t, err)
	for _, secret := range []string{"secret-session-token-abc123", "secret-extract-abcd1234"} {
		assert.NotContains(t, string(marshaled), secret, "parsed model must not carry request/response bodies")
	}

	redacted := redact(t, data)
	for _, secret := range []string{"secret-session-token-abc123", "secret-extract-abcd1234"} {
		assert.NotContains(t, string(redacted), secret)
	}
	assert.Contains(t, string(redacted), "[REDACTED]")
	assert.Contains(t, string(redacted), "http-missing-security-headers")
	// Redacted output still parses to the same identities.
	rep2, err := NewScanner().Parse(context.Background(), redacted)
	require.NoError(t, err)
	require.Len(t, rep2.Findings, 3)
	assert.Equal(t, rep.Findings[1].Fingerprint, rep2.Findings[1].Fingerprint)
}

func TestParseSkipsMalformedLines(t *testing.T) {
	data := "{bad json}\n" + `{"template-id":"t","host":"https://h.example.com"}` + "\n"
	rep, err := NewScanner().Parse(context.Background(), []byte(data))
	require.NoError(t, err)
	require.Len(t, rep.Findings, 1)
	require.NotNil(t, rep.ScanScope)
	assert.Equal(t, "1", rep.ScanScope.Ext["skipped_lines"])
	assert.True(t, strings.HasPrefix(rep.Findings[0].Fingerprint, "dast:t:https://h.example.com"))
}

func dimValue(f domain.NormalizedFinding, key string) string {
	for _, d := range f.Dimensions {
		if d.Key == key {
			return d.Value
		}
	}
	return ""
}

func paramValues(f domain.NormalizedFinding) []string {
	var out []string
	for _, d := range f.Dimensions {
		if d.Key == "parameter" {
			out = append(out, d.Value)
		}
	}
	return out
}

func TestRedactRawIsCaseInsensitiveAndNested(t *testing.T) {
	doc := `[{"template-id":"t","host":"h","Request":"GET /?token=abc","RESPONSE":"Set-Cookie: session=xyz","Extracted-Results":["leak-1"],"EXTRACTED_RESULTS":["leak-2"],"request":"GET /?k=v",` +
		`"info":{"name":"n","nested":{"Response":"nested-body","list":[{"REQUEST":"list-body"}]}}}]`
	redacted := string(redact(t, []byte(doc)))
	for _, leaked := range []string{"token=abc", "session=xyz", "leak-1", "leak-2", "k=v", "nested-body", "list-body"} {
		assert.NotContains(t, redacted, leaked)
	}
	assert.Contains(t, redacted, `"template-id":"t"`, "provenance survives")
}

func TestRedactRawIsCaseInsensitiveForJSONLines(t *testing.T) {
	doc := `{"template-id":"t","host":"h","Request":"GET /?token=abc"}` + "\n" +
		`{"template-id":"u","host":"h","RESPONSE":"body-secret"}` + "\n"
	redacted := string(redact(t, []byte(doc)))
	assert.NotContains(t, redacted, "token=abc")
	assert.NotContains(t, redacted, "body-secret")
	assert.Contains(t, redacted, `"template-id":"u"`)
}

// A line over the 1 MiB scanner buffer used to end the scan quietly and drop
// every later event from the stored evidence.
func TestAnOverlongJSONLineIsAnErrorNotSilentlyDropped(t *testing.T) {
	long := `{"template-id":"big","host":"h","request":"` + strings.Repeat("x", 2<<20) + `"}`
	doc := `{"template-id":"first","host":"h"}` + "\n" + long + "\n" + `{"template-id":"last","host":"h"}` + "\n"

	_, err := NewScanner().Parse(context.Background(), []byte(doc))
	require.Error(t, err)
	require.ErrorIs(t, err, scanner.ErrMalformedReport)

	out, err := NewScanner().RedactRaw([]byte(doc))
	require.ErrorIs(t, err, scanner.ErrRedactionFailed, "an unreadable document is never stored as a shortened one")
	assert.Empty(t, out)
}

// A document the redactor cannot read is an error and never comes back as it
// went in: it may still hold a request or response body.
func TestRedactRawNeverReturnsWhatItCouldNotRedact(t *testing.T) {
	const secret = "NUCLEIBEARERTOKEN0001"
	nested := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	event := func(extra string) string {
		return `{"template-id":"t","host":"http://h","matched-at":"http://h/","info":{"name":"n","severity":"high"},"request":"GET / HTTP/1.1\r\nAuthorization: Bearer ` + secret + `\r\n"` + extra + `}`
	}
	cases := map[string]string{
		"empty":                  ``,
		"blank":                  " \n\t ",
		"trailing garbage":       `[` + event("") + `]garbage`,
		"a second array":         `[` + event("") + `][]`,
		"nesting past the limit": `[` + event(`,"x":`+nested) + `]`,
		"an array of strings":    `["` + secret + `"]`,
		"an unterminated array":  `[` + event(""),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := NewScanner().RedactRaw([]byte(doc))

			require.ErrorIs(t, err, scanner.ErrRedactionFailed)
			assert.Empty(t, out, "nothing derived from the input is returned")
		})
	}
}

// A line the parser skips as malformed is left out of the stored evidence, not
// stored as it came: its request text may hold a credential.
func TestRedactRawLeavesMalformedLinesOut(t *testing.T) {
	const secret = "NUCLEIMALFORMEDTOKEN02"
	doc := `{"template-id":"ok","host":"h"}` + "\n" +
		`{"template-id":"bad","request":"Bearer ` + secret + `"` + "\n" + // unterminated object
		`{"template-id":"nest","request":"Bearer ` + secret + `","x":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}` + "\n"

	out := redact(t, []byte(doc))

	assert.NotContains(t, string(out), secret)
	assert.Contains(t, string(out), `"template-id":"ok"`)
}

// A number that does not fit a float64 in a field the parser ignores used to
// make the redactor fail and hand back the input with the request in it. The
// document parses, so it has to be redacted.
func TestRedactRawToleratesNumbersThatOverflowAFloat(t *testing.T) {
	const secret = "NUCLEIOVERFLOWTOKEN003"
	for _, number := range []string{"1e400", "-1e999", "123456789012345678901234567890"} {
		event := `{"template-id":"t","host":"http://h","matched-at":"http://h/","info":{"name":"n","severity":"high"},` +
			`"request":"GET / HTTP/1.1\r\nAuthorization: Bearer ` + secret + `\r\n","response":"Set-Cookie: s=` + secret + `","x":` + number + `,"curl":{"response":"` + secret + `"}}`
		for name, doc := range map[string]string{"array": `[` + event + `]`, "lines": event + "\n"} {
			_, err := NewScanner().Parse(context.Background(), []byte(doc))
			require.NoError(t, err, "the typed parser ignores the field, so the report is ingested")

			out := redact(t, []byte(doc))

			assert.NotContains(t, string(out), secret, "%s %s", name, number)
			assert.True(t, json.Valid(out), "the stored evidence is valid JSON: %s", out)
			assert.Contains(t, string(out), "[REDACTED]")
			assert.Contains(t, string(out), number, "the number itself survives as written")
		}
	}
}

func redact(t *testing.T, data []byte) []byte {
	t.Helper()
	out, err := NewScanner().RedactRaw(data)
	require.NoError(t, err)
	return out
}
