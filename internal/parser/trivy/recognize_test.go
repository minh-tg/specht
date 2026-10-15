package trivy

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/scanner"
)

func TestRecognize(t *testing.T) {
	scan, err := os.ReadFile("testdata/alpine-scan.json")
	require.NoError(t, err)
	empty, err := os.ReadFile("testdata/empty-scan.json")
	require.NoError(t, err)

	for name, tc := range map[string]struct {
		data string
		want scanner.Recognition
	}{
		"a scan with results":                {string(scan), scanner.Definite},
		"a clean scan":                       {string(empty), scanner.Definite},
		"a named artifact and no results":    {`{"SchemaVersion":2,"ArtifactName":"app","Results":null}`, scanner.Definite},
		"a result with a target":             {`{"Results":[{"Target":"package-lock.json"}]}`, scanner.Definite},
		"the legacy list of results":         {`[{"Target":"alpine:3.12","Vulnerabilities":[]}]`, scanner.Definite},
		"only a schema version":              {`{"SchemaVersion":2}`, scanner.Possible},
		"an empty array":                     {`[]`, scanner.NotRecognized},
		"an empty object":                    {`{}`, scanner.NotRecognized},
		"null":                               {`null`, scanner.NotRecognized},
		"not JSON":                           {`not json`, scanner.NotRecognized},
		"a grype report":                     {`{"matches":[],"descriptor":{"name":"grype"}}`, scanner.NotRecognized},
		"a gosec report":                     {`{"Golang errors":{},"Issues":[],"Stats":{}}`, scanner.NotRecognized},
		"a SARIF log":                        {`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[]}]}`, scanner.NotRecognized},
		"a CycloneDX document":               {`{"bomFormat":"CycloneDX","components":[]}`, scanner.NotRecognized},
		"a list of hadolint messages":        {`[{"code":"DL3006","level":"warning","file":"Dockerfile","line":1}]`, scanner.NotRecognized},
		"an npm audit report":                {`{"auditReportVersion":2,"vulnerabilities":{},"metadata":{}}`, scanner.NotRecognized},
		"a list of gitleaks findings":        {`[{"RuleID":"generic-api-key","File":"a.env"}]`, scanner.NotRecognized},
		"an object whose results are a text": {`{"results":"x"}`, scanner.NotRecognized},
	} {
		t.Run(name, func(t *testing.T) {
			s := NewScanner()
			assert.Equal(t, tc.want, s.Recognize([]byte(tc.data)))
			assert.Equal(t, tc.want == scanner.Definite, s.DetectFormat([]byte(tc.data)),
				"DetectFormat is the definite grade")
		})
	}
}

func TestParseRefusesWhatIsNotTrivy(t *testing.T) {
	_, err := NewScanner().Parse(context.Background(), []byte(`{"Golang errors":{},"Issues":[]}`))
	require.ErrorIs(t, err, scanner.ErrUnrecognizedFormat)
	var fe *scanner.UnrecognizedFormatError
	require.ErrorAs(t, err, &fe)
	assert.Equal(t, "trivy", fe.Scanner)
}

func TestParseAcceptsACleanScan(t *testing.T) {
	empty, err := os.ReadFile("testdata/empty-scan.json")
	require.NoError(t, err)
	nr, err := NewScanner().Parse(context.Background(), empty)
	require.NoError(t, err)
	assert.Empty(t, nr.Findings)
}

func TestParseCallsAnUnreadableTrivyReportMalformed(t *testing.T) {
	_, err := NewScanner().Parse(context.Background(), []byte(`{"SchemaVersion":2,"ArtifactName":"app","Results":"oops"}`))
	require.ErrorIs(t, err, scanner.ErrMalformedReport)
	assert.NotErrorIs(t, err, scanner.ErrUnrecognizedFormat)
}
