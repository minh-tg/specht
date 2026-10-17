package checkov_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/checkov"
	"github.com/minh-tg/specht/internal/scanner"
)

const checkovSecret = "AKIATESTSECRETVALUE01"

// checkovSecretCheck is one failed check whose source and variable evaluation
// both hold the secret.
const checkovSecretCheck = `{"check_id":"CKV_AWS_41","check_name":"Ensure no hard-coded AWS access key","check_result":{"result":"FAILED"},"file_path":"/main.tf","file_line_range":[3,4],"resource":"aws_instance.web","check_class":"checkov.terraform.checks.provider.aws.Secrets","guideline":"https://example.test/CKV_AWS_41","severity":"HIGH","code_block":[[3,"  key = \"` + checkovSecret + `\"\n"]],"evaluations":{"access_key":{"var_file":"terraform.tfvars","var_definitions":[{"value":"` + checkovSecret + `"}]}}}`

var checkovSecretDocs = map[string][]byte{
	"object": []byte(`{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[` + checkovSecretCheck + `],"skipped_checks":[],"parsing_errors":[]},"summary":{"passed":0,"failed":1,"skipped":0,"parsing_errors":0,"checkov_version":"3.0.0"}}`),
	"array":  []byte(`[{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[` + checkovSecretCheck + `],"skipped_checks":[],"parsing_errors":[]},"summary":{"passed":0,"failed":1,"skipped":0,"parsing_errors":0,"checkov_version":"3.0.0"}},{"check_type":"cloudformation","results":{"passed_checks":[],"failed_checks":[],"skipped_checks":[],"parsing_errors":[]},"summary":{"passed":0,"failed":0,"skipped":0,"parsing_errors":0,"checkov_version":"3.0.0"}}]`),
}

func TestRedactRawRemovesTheSecretAndTheFindingStillIngests(t *testing.T) {
	for shape, data := range checkovSecretDocs {
		t.Run(shape, func(t *testing.T) {
			s := checkov.NewScanner()
			original, err := s.Parse(context.Background(), data)
			require.NoError(t, err)
			require.Len(t, original.Findings, 1)

			redacted, err := s.RedactRaw(data)
			require.NoError(t, err)

			assert.NotContains(t, string(redacted), checkovSecret)
			assert.Contains(t, string(redacted), "[REDACTED]")
			assert.Contains(t, string(redacted), "CKV_AWS_41", "provenance survives redaction")

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
	doc := checkovSecretDocs["object"]
	cases := map[string][]byte{
		"not json":         []byte(`not json`),
		"truncated":        doc[:len(doc)-3],
		"a second value":   append(append([]byte{}, doc...), []byte(`{}`)...),
		"trailing garbage": append(append([]byte{}, doc...), []byte(`x`)...),
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := checkov.NewScanner().RedactRaw(data)

			require.ErrorIs(t, err, scanner.ErrRedactionFailed)
			assert.Empty(t, out)
		})
	}
}

// A report over the cap keeps its first RawEvidenceCap bytes in a JSON wrapper
// with the size of the raw output. The check name is not a redacted key, so
// the size is the report's own.
func TestRedactRawCapsAReportOf200KiB(t *testing.T) {
	data := []byte(`{"check_type":"terraform","results":{"passed_checks":[],"failed_checks":[{"check_id":"CKV_AWS_1","check_name":"` + strings.Repeat("n", 200<<10) + `","check_result":{"result":"FAILED"},"file_path":"/main.tf","file_line_range":[1,2],"resource":"aws_s3_bucket.b","severity":"LOW"}],"skipped_checks":[],"parsing_errors":[]},"summary":{"passed":0,"failed":1,"skipped":0,"parsing_errors":0,"checkov_version":"3.0.0"}}`)
	require.Greater(t, len(data), 200<<10)

	out, err := checkov.NewScanner().RedactRaw(data)
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
