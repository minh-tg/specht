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

	redacted := NewScanner().RedactRaw(data)
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
	redacted := string(NewScanner().RedactRaw([]byte(doc)))
	for _, leaked := range []string{"token=abc", "session=xyz", "leak-1", "leak-2", "k=v", "nested-body", "list-body"} {
		assert.NotContains(t, redacted, leaked)
	}
	assert.Contains(t, redacted, `"template-id":"t"`, "provenance survives")
}

func TestRedactRawIsCaseInsensitiveForJSONLines(t *testing.T) {
	doc := `{"template-id":"t","host":"h","Request":"GET /?token=abc"}` + "\n" +
		`{"template-id":"u","host":"h","RESPONSE":"body-secret"}` + "\n"
	redacted := string(NewScanner().RedactRaw([]byte(doc)))
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

	got := NewScanner().RedactRaw([]byte(doc))
	assert.Equal(t, doc, string(got), "an unreadable document is never stored as a shortened one")
}
