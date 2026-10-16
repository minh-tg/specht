package gitleaks

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

// secretsInFixture returns every secret-material string in the fixture. The
// parsed model and the redacted raw bytes must contain none of them.
func secretsInFixture(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile("testdata/gitleaks.json")
	require.NoError(t, err)
	var findings []map[string]any
	require.NoError(t, json.Unmarshal(data, &findings))
	var out []string
	for _, f := range findings {
		for _, k := range []string{"Secret", "Match"} {
			if s, ok := f[k].(string); ok && s != "" {
				out = append(out, s)
			}
		}
	}
	require.NotEmpty(t, out, "fixture must contain realistic secret material to prove redaction")
	return out
}

// keyedContext carries the instance key a Gitleaks parse needs to identify secrets.
func keyedContext() context.Context {
	return scanner.WithFingerprintKey(context.Background(), []byte("0123456789abcdef0123456789abcdef"))
}

func TestParseRedactsSecretMaterial(t *testing.T) {
	data, err := os.ReadFile("testdata/gitleaks.json")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(keyedContext(), data)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 3)

	marshaled, err := json.Marshal(rep)
	require.NoError(t, err)
	for _, secret := range secretsInFixture(t) {
		assert.NotContains(t, string(marshaled), secret, "parsed model must never carry secret material")
	}
}

func TestParseShapes(t *testing.T) {
	data, err := os.ReadFile("testdata/gitleaks.json")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(keyedContext(), data)
	require.NoError(t, err)

	aws := rep.Findings[0]
	assert.Regexp(t, `^secret:aws-access-key:deploy/creds\.env:[0-9a-f]{32}$`, aws.Fingerprint,
		"rule, file and a keyed digest of the credential")
	assert.Equal(t, "secret", aws.FindingKind)
	assert.Equal(t, domain.SeverityHigh, aws.Severity)
	assert.Equal(t, "deploy/creds.env:12", aws.Location)
	assert.Equal(t, "AWS Access Key", aws.Title)
	require.NotNil(t, aws.Fix)
	assert.Contains(t, aws.Fix.Summary, "Revoke")
	require.NotNil(t, aws.CodeLocation)
	assert.Equal(t, "deploy/creds.env", aws.CodeLocation.File)
	assert.Equal(t, "9f2c1ab4e8d34f21a0b6c8d9e0f1a2b3c4d5e6f7", aws.Extensions["commit"])
}

func TestRedactRaw(t *testing.T) {
	data, err := os.ReadFile("testdata/gitleaks.json")
	require.NoError(t, err)
	redacted := redact(t, data)
	for _, secret := range secretsInFixture(t) {
		assert.NotContains(t, string(redacted), secret)
	}
	assert.Contains(t, string(redacted), "[REDACTED]")
	// Provenance survives; redacted output still parses identically.
	assert.Contains(t, string(redacted), "aws-access-key")
	assert.Contains(t, string(redacted), "9f2c1ab4e8d34f21a0b6c8d9e0f1a2b3c4d5e6f7")
	rep, err := NewScanner().Parse(keyedContext(), redacted)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 3)
	assert.Regexp(t, `^secret:aws-access-key:deploy/creds\.env:[0-9a-f]{32}$`, rep.Findings[0].Fingerprint)
	assert.NotEqual(t, "secret", rep.Findings[0].Extensions["identity_basis"],
		"redacted evidence has no credential left to hash, and says so")
}

func TestRedactRawOfAnEmptyArray(t *testing.T) {
	assert.Equal(t, `[]`, string(redact(t, []byte(`[]`))))
}

// A document the redactor cannot read is an error and never comes back as it
// went in: it may still hold the Secret.
func TestRedactRawNeverReturnsWhatItCouldNotRedact(t *testing.T) {
	const secret = "AKIAFAILCLOSEDSECRET01"
	nested := strings.Repeat("[", 20000) + strings.Repeat("]", 20000)
	entry := func(extra string) string {
		return `{"RuleID":"aws","File":"a.env","StartLine":1,"Secret":"` + secret + `","Match":"key=` + secret + `"` + extra + `}`
	}
	cases := map[string]string{
		"not json":               `not json`,
		"trailing garbage":       `[` + entry("") + `]garbage`,
		"a second value":         `[` + entry("") + `][]`,
		"nesting past the limit": `[` + entry(`,"x":`+nested) + `]`,
		"not an array":           entry(""),
		"an array of strings":    `["` + secret + `"]`,
		"an unterminated array":  `[` + entry(""),
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := NewScanner().RedactRaw([]byte(doc))

			require.ErrorIs(t, err, scanner.ErrRedactionFailed)
			assert.Empty(t, out, "nothing derived from the input is returned")
		})
	}
}

// A number that does not fit a float64 in a field the parser ignores used to
// make the redactor fail and hand back the input with the Secret in it. The
// document parses, so it has to be redacted.
func TestRedactRawToleratesNumbersThatOverflowAFloat(t *testing.T) {
	const secret = "AKIAOVERFLOWSECRET0001"
	for _, number := range []string{"1e400", "-1e999", "123456789012345678901234567890", "1E+500", "0.000000000000000000000000000000001"} {
		doc := `[{"RuleID":"aws","File":"a.env","StartLine":1,"Secret":"` + secret + `","Match":"key=` + secret + `","x":` + number + `,"nested":{"y":[` + number + `],"secret":"` + secret + `"}}]`
		_, err := NewScanner().Parse(keyedContext(), []byte(doc))
		require.NoError(t, err, "the typed parser ignores the field, so the report is ingested")

		out := redact(t, []byte(doc))

		assert.NotContains(t, string(out), secret, number)
		assert.True(t, json.Valid(out), "the stored evidence is valid JSON: %s", out)
		assert.Contains(t, string(out), "[REDACTED]")
		assert.Contains(t, string(out), number, "the number itself survives as written")
	}
}

func redact(t *testing.T, data []byte) []byte {
	t.Helper()
	out, err := NewScanner().RedactRaw(data)
	require.NoError(t, err)
	return out
}

func TestDetectFormat(t *testing.T) {
	data, err := os.ReadFile("testdata/gitleaks.json")
	require.NoError(t, err)
	assert.True(t, NewScanner().DetectFormat(data))
	assert.False(t, NewScanner().DetectFormat([]byte(`[{"Target":"x"}]`)))
}

// encoding/json matches struct fields without regard to case, so the parser
// reads (and hashes) a key like "secret" that the redactor used to leave alone.
func TestRedactRawIsCaseInsensitive(t *testing.T) {
	const secret = "hunter2-super-secret"
	for _, key := range []string{"Secret", "secret", "sEcReT", "SECRET"} {
		for _, matchKey := range []string{"Match", "match", "MATCH"} {
			doc := `[{"RuleID":"generic","File":"a.env","` + key + `":"` + secret + `","` + matchKey + `":"token=` + secret + `","StartLine":1}]`
			redacted := string(redact(t, []byte(doc)))
			assert.NotContains(t, redacted, secret, "keys %s and %s", key, matchKey)
			assert.Contains(t, redacted, "generic", "provenance survives")
		}
	}
}

func TestRedactRawCoversEveryCaseVariantOfTheSameKey(t *testing.T) {
	doc := `[{"RuleID":"r","File":"f","Secret":"first-secret","secret":"second-secret"}]`
	redacted := string(redact(t, []byte(doc)))
	assert.NotContains(t, redacted, "first-secret")
	assert.NotContains(t, redacted, "second-secret")
}

func TestRedactRawCoversNestedObjectsAndLists(t *testing.T) {
	doc := `[{"RuleID":"r","File":"f","Secret":"top","extra":{"secret":"nested-secret","deeper":[{"MATCH":"list-secret"}]}}]`
	redacted := string(redact(t, []byte(doc)))
	for _, leaked := range []string{"nested-secret", "list-secret"} {
		assert.NotContains(t, redacted, leaked)
	}
}

func TestRedactRawKeepsTheIdentityBasisOfACaseVariantReport(t *testing.T) {
	doc := []byte(`[{"RuleID":"generic","File":"a.env","secret":"hunter2-super-secret","StartLine":1}]`)
	redacted := redact(t, doc)
	rep, err := NewScanner().Parse(keyedContext(), redacted)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 1)
	assert.NotEqual(t, "secret", rep.Findings[0].Extensions["identity_basis"], "no credential is left to hash")
}
