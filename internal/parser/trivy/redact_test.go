package trivy_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/trivy"
	"github.com/minh-tg/specht/internal/scanner"
)

const trivySecret = "AKIATESTSECRETVALUE01"

var trivySecretDoc = []byte(`{"SchemaVersion":2,"ArtifactName":"repo","ArtifactType":"filesystem","Results":[{"Target":"./app/.env","Class":"secret","Secrets":[{"RuleID":"aws-access-key-id","Category":"AWS","Severity":"CRITICAL","Title":"AWS Access Key ID","Match":"AWS_KEY=` + trivySecret + `","Code":{"Lines":[{"Number":1,"Content":"AWS_KEY=` + trivySecret + `"}]}}]}]}`)

func TestRedactRawRemovesTheSecretAndTheFindingStillIngests(t *testing.T) {
	s := trivy.NewScanner()
	original, err := s.Parse(context.Background(), trivySecretDoc)
	require.NoError(t, err)
	require.Len(t, original.Findings, 1)

	redacted, err := s.RedactRaw(trivySecretDoc)
	require.NoError(t, err)

	assert.NotContains(t, string(redacted), trivySecret)
	assert.Contains(t, string(redacted), "[REDACTED]")
	assert.Contains(t, string(redacted), "aws-access-key-id", "provenance survives redaction")

	again, err := s.Parse(context.Background(), redacted)
	require.NoError(t, err, "redacted evidence still parses")
	require.Len(t, again.Findings, 1)
	assert.Equal(t, original.Findings[0].Fingerprint, again.Findings[0].Fingerprint)
	assert.Equal(t, original.Findings[0].Title, again.Findings[0].Title)
	assert.Equal(t, original.Findings[0].Severity, again.Findings[0].Severity)
}

// Each of these is a document the parser's decoder cannot read as one JSON
// value. The redactor must refuse them and return nothing, so the caller stores
// the failed marker instead of the input.
func TestRedactRawFailsClosedOnUndecodableInput(t *testing.T) {
	cases := map[string][]byte{
		"not json":         []byte(`not json`),
		"truncated":        trivySecretDoc[:len(trivySecretDoc)-5],
		"a second value":   append(append([]byte{}, trivySecretDoc...), []byte(`{}`)...),
		"trailing garbage": append(append([]byte{}, trivySecretDoc...), []byte(`x`)...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := trivy.NewScanner().RedactRaw(data)

			require.ErrorIs(t, err, scanner.ErrRedactionFailed)
			assert.Empty(t, out)
		})
	}
}

// A report over the cap keeps its first RawEvidenceCap bytes in a JSON wrapper
// with the size of the raw output. The description is not a redacted key, so
// the size is the report's own.
func TestRedactRawCapsAReportOf200KiB(t *testing.T) {
	data := []byte(`{"SchemaVersion":2,"ArtifactName":"repo","ArtifactType":"filesystem","Results":[{"Target":"go.sum","Class":"lang-pkgs","Vulnerabilities":[{"VulnerabilityID":"CVE-2024-0001","PkgName":"pkg","InstalledVersion":"1.0.0","Severity":"HIGH","Description":"` + strings.Repeat("d", 200<<10) + `"}]}]}`)
	require.Greater(t, len(data), 200<<10)

	out, err := trivy.NewScanner().RedactRaw(data)
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

func TestRedactRawLeavesASmallReportWhole(t *testing.T) {
	out, err := trivy.NewScanner().RedactRaw(trivySecretDoc)
	require.NoError(t, err)

	assert.NotContains(t, string(out), "truncated")
}

// credentialKeysAtDepth puts a credential at the root object (depth 1) and
// under four nested objects (depth 5). Each value is unique, so NotContains
// fails if any of them survives.
const credentialKeysAtDepth = `"password":"pw-depth-1","token":"tok-depth-1","api_key":"key-depth-1","db_password":"dbpass-depth-1","auth_token":"auth-depth-1","Authorization":"authz-depth-1","client_secret":"cs-depth-1","tokenizer_version":"tokenizer-depth-1","nest":{"a":{"b":{"c":{"password":"pw-depth-5","token":"tok-depth-5","api_key":"key-depth-5","db_password":"dbpass-depth-5","auth_token":"auth-depth-5","Authorization":"authz-depth-5","client_secret":"cs-depth-5","tokenizer_version":"tokenizer-depth-5"}}}},`

var credentialValuesAtDepth = []string{"pw-depth-1", "tok-depth-1", "key-depth-1", "dbpass-depth-1", "auth-depth-1", "authz-depth-1", "cs-depth-1", "tokenizer-depth-1", "pw-depth-5", "tok-depth-5", "key-depth-5", "dbpass-depth-5", "auth-depth-5", "authz-depth-5", "cs-depth-5", "tokenizer-depth-5"}

func TestRedactRawRedactsCredentialKeysAtDepthOneAndFive(t *testing.T) {
	data := []byte(strings.Replace(string(trivySecretDoc), "{", "{"+credentialKeysAtDepth, 1))
	s := trivy.NewScanner()
	redacted, err := s.RedactRaw(data)
	require.NoError(t, err)

	for _, v := range append(credentialValuesAtDepth, trivySecret) {
		assert.NotContains(t, string(redacted), v)
	}
	assert.Contains(t, string(redacted), `"api_key":"[REDACTED]"`)

	_, err = s.Parse(context.Background(), redacted)
	require.NoError(t, err, "redacted evidence still parses")
}

// dbPasswordAtDepth puts db_password at the root object (depth 1) and under four
// nested objects (depth 5). shallow and deep are the JSON values at each depth.
func dbPasswordAtDepth(doc []byte, shallow, deep string) []byte {
	return []byte(strings.Replace(string(doc), "{", `{"db_password":`+shallow+`,"nest":{"a":{"b":{"c":{"db_password":`+deep+`}}}},`, 1))
}

// TestRedactRawRedactsScalarElementsOfADbPasswordList covers a credential name
// whose value is a list of scalars at depth 1 and depth 5. Each scalar has no
// key, so the walk must replace it directly. The Secrets objects keep RuleID
// and Title, and the stored evidence still decodes to one finding.
func TestRedactRawRedactsScalarElementsOfADbPasswordList(t *testing.T) {
	data := dbPasswordAtDepth(trivySecretDoc, `["dbpass-list-1"]`, `["dbpass-list-5"]`)
	s := trivy.NewScanner()
	redacted, err := s.RedactRaw(data)
	require.NoError(t, err)

	assert.NotContains(t, string(redacted), "dbpass-")
	assert.Equal(t, 2, strings.Count(string(redacted), `"db_password":["[REDACTED]"]`))
	assert.Contains(t, string(redacted), `"RuleID":"aws-access-key-id"`)
	assert.Contains(t, string(redacted), `"Title":"AWS Access Key ID"`)

	report, err := s.Parse(context.Background(), redacted)
	require.NoError(t, err, "redacted evidence still parses")
	require.Len(t, report.Findings, 1)
}

// TestRedactRawRedactsDbPasswordHoldingAStringOrAnObject checks that the whole
// db_password value is gone at both depths. The sentinel "dbpass-" appears in
// every value, so NotContains fails if any part of one survives.
func TestRedactRawRedactsDbPasswordHoldingAStringOrAnObject(t *testing.T) {
	shapes := map[string][2]string{
		"string": {`"dbpass-str-1"`, `"dbpass-str-5"`},
		"object": {`{"value":"dbpass-obj-1","inner":{"deeper":"dbpass-obj-1b"}}`, `{"value":"dbpass-obj-5"}`},
	}
	for shape, v := range shapes {
		t.Run(shape, func(t *testing.T) {
			s := trivy.NewScanner()
			redacted, err := s.RedactRaw(dbPasswordAtDepth(trivySecretDoc, v[0], v[1]))
			require.NoError(t, err)

			assert.NotContains(t, string(redacted), "dbpass-")
			assert.Equal(t, 2, strings.Count(string(redacted), `"db_password":"[REDACTED]"`))
			_, err = s.Parse(context.Background(), redacted)
			require.NoError(t, err, "redacted evidence still parses")
		})
	}
}
