package trivy_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/trivy"
)

const trivyImageDoc = `{"SchemaVersion":2,"ArtifactName":"app:1","ArtifactType":"container_image",` +
	`"Metadata":{"OS":{"Family":"alpine","Name":"3.20"},"ImageConfig":{"architecture":"amd64",` +
	`"config":{"Env":["PATH=/usr/bin","DB_PASSWORD=img-env-secret-1","EMPTY=","NOEQUALS-img-env-secret-2"],"Cmd":["/app"]},` +
	`"container_config":{"Env":["API_TOKEN=img-env-secret-3"]},` +
	`"history":[{"created":"2024-01-01T00:00:00Z","created_by":"RUN curl -u admin:img-hist-secret-1 https://x","empty_layer":false},` +
	`{"created_by":""},{"comment":"base"}]}},` +
	`"Results":[{"Target":"app:1 (alpine 3.20)","Class":"os-pkgs","Type":"alpine","Vulnerabilities":[` +
	`{"VulnerabilityID":"CVE-2024-0001","PkgName":"musl","InstalledVersion":"1.0","Severity":"HIGH","Title":"t"}]}]}`

func TestRedactRawRedactsTheImageConfigEnvValuesAndHistoryCommands(t *testing.T) {
	s := trivy.NewScanner()
	original, err := s.Parse(context.Background(), []byte(trivyImageDoc))
	require.NoError(t, err)

	redacted, err := s.RedactRaw([]byte(trivyImageDoc))
	require.NoError(t, err)

	assert.NotContains(t, string(redacted), "img-env-secret")
	assert.NotContains(t, string(redacted), "img-hist-secret")
	assert.Contains(t, string(redacted), `"DB_PASSWORD=[REDACTED]"`, "the variable name stays")
	assert.Contains(t, string(redacted), `"API_TOKEN=[REDACTED]"`)
	assert.Contains(t, string(redacted), `"PATH=[REDACTED]"`)
	assert.Contains(t, string(redacted), `"EMPTY="`, "an empty value has nothing to redact")
	assert.Contains(t, string(redacted), `"created_by":"[REDACTED]"`)
	assert.Contains(t, string(redacted), `"created_by":""`, "an empty command stays empty")
	assert.Contains(t, string(redacted), `"architecture":"amd64"`)

	again, err := s.Parse(context.Background(), redacted)
	require.NoError(t, err, "redacted evidence still parses")
	require.Equal(t, len(original.Findings), len(again.Findings))
	assert.Equal(t, original.Findings[0].Fingerprint, again.Findings[0].Fingerprint)
}

// encoding/json reads struct fields in any case, so the image config is found
// under any spelling of its keys.
func TestRedactRawRedactsTheImageConfigUnderOtherKeyCases(t *testing.T) {
	data := []byte(`{"metadata":{"imageconfig":{"CONFIG":{"env":["K=img-case-secret-1"]},` +
		`"History":[{"Created_By":"img-case-secret-2"}]}}}`)
	redacted, err := trivy.NewScanner().RedactRaw(data)
	require.NoError(t, err)

	assert.NotContains(t, string(redacted), "img-case-secret")
}

func TestRedactRawLeavesAReportWithoutImageConfigAlone(t *testing.T) {
	data := []byte(`{"SchemaVersion":2,"ArtifactName":"repo","ArtifactType":"filesystem","Metadata":{"env":["A=b"]},"Results":[]}`)
	redacted, err := trivy.NewScanner().RedactRaw(data)
	require.NoError(t, err)

	assert.JSONEq(t, string(data), string(redacted))
}
