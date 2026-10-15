package sbom_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/sbom"
	"github.com/minh-tg/specht/internal/scanner"
)

func TestRecognize(t *testing.T) {
	s := sbom.NewScanner()

	for file, want := range map[string]scanner.Recognition{
		"testdata/cyclonedx.json": scanner.Definite,
		"testdata/spdx.json":      scanner.Definite,
	} {
		t.Run(file, func(t *testing.T) {
			data, err := os.ReadFile(file)
			require.NoError(t, err)
			assert.Equal(t, want, s.Recognize(data))
		})
	}

	for name, tc := range map[string]struct {
		data string
		want scanner.Recognition
	}{
		"an SPDX document":                   {`{"spdxVersion":"SPDX-2.3","packages":[]}`, scanner.Definite},
		"a bom format that is not CycloneDX": {`{"bomFormat":"Other"}`, scanner.NotRecognized},
		"an SPDX version that is not SPDX":   {`{"spdxVersion":"3.0"}`, scanner.NotRecognized},
		"a gosec report":                     {`{"Golang errors":{},"Issues":[{"severity":"HIGH","rule_id":"G201"}],"Stats":{}}`, scanner.NotRecognized},
		"a bandit report":                    {`{"errors":[],"generated_at":"2026-10-14T00:00:00Z","metrics":{},"results":[{"test_id":"B101","issue_text":"x","filename":"a.py"}]}`, scanner.NotRecognized},
		"an npm audit report":                {`{"auditReportVersion":2,"vulnerabilities":{},"metadata":{}}`, scanner.NotRecognized},
		"a list of hadolint messages":        {`[{"code":"DL3006","level":"warning","message":"x","file":"Dockerfile","line":1}]`, scanner.NotRecognized},
		"a SARIF log of another tool":        {`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"other"}},"results":[]}]}`, scanner.NotRecognized},
		"a CycloneDX document":               {`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`, scanner.Definite},
		"an empty array":                     {`[]`, scanner.NotRecognized},
		"an empty object":                    {`{}`, scanner.NotRecognized},
		"null":                               {`null`, scanner.NotRecognized},
		"not JSON":                           {`not json`, scanner.NotRecognized},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, s.Recognize([]byte(tc.data)))
			assert.Equal(t, tc.want == scanner.Definite, s.DetectFormat([]byte(tc.data)), "DetectFormat is the definite grade")
		})
	}
}

func TestParseRefusesWhatIsNotThisTool(t *testing.T) {
	s := sbom.NewScanner()
	for name, data := range map[string]string{
		"a gosec report":              `{"Golang errors":{},"Issues":[{"severity":"HIGH","rule_id":"G201"}],"Stats":{}}`,
		"a bandit report":             `{"errors":[],"generated_at":"2026-10-14T00:00:00Z","metrics":{},"results":[{"test_id":"B101","issue_text":"x","filename":"a.py"}]}`,
		"an npm audit report":         `{"auditReportVersion":2,"vulnerabilities":{},"metadata":{}}`,
		"a list of hadolint messages": `[{"code":"DL3006","level":"warning","message":"x","file":"Dockerfile","line":1}]`,
		"a SARIF log of another tool": `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"other"}},"results":[]}]}`,
		"an empty array":              `[]`,
		"an empty object":             `{}`,
		"null":                        `null`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.Parse(context.Background(), []byte(data))
			require.ErrorIs(t, err, scanner.ErrUnrecognizedFormat)
			var fe *scanner.UnrecognizedFormatError
			require.ErrorAs(t, err, &fe)
			assert.Equal(t, "sbom", fe.Scanner)
		})
	}
}

func TestParseAcceptsAnEmptyReport(t *testing.T) {
	s := sbom.NewScanner()
	for name, data := range map[string]string{
		"a CycloneDX document": `{"bomFormat":"CycloneDX","specVersion":"1.5"}`,
		"an SPDX document":     `{"spdxVersion":"SPDX-2.3","packages":[]}`,
	} {
		t.Run(name, func(t *testing.T) {
			nr, err := s.Parse(context.Background(), []byte(data))
			require.NoError(t, err)
			assert.Empty(t, nr.Findings)
		})
	}
}

func TestParseCallsAnUnreadableReportMalformed(t *testing.T) {
	_, err := sbom.NewScanner().Parse(context.Background(), []byte(`{"bomFormat":"CycloneDX","components":"oops"}`))
	require.ErrorIs(t, err, scanner.ErrMalformedReport)
	assert.NotErrorIs(t, err, scanner.ErrUnrecognizedFormat)
}
