package tfsec_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser/tfsec"
	"github.com/minh-tg/specht/internal/scanner"
)

func TestRecognize(t *testing.T) {
	s := tfsec.NewScanner()

	for file, want := range map[string]scanner.Recognition{
		"testdata/tfsec.json": scanner.Definite,
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
		"results with statistics":     {`{"results":[],"statistics":{}}`, scanner.Definite},
		"results of tfsec rules":      {`{"results":[{"rule_id":"a","long_id":"a-b"}]}`, scanner.Definite},
		"empty results":               {`{"results":[]}`, scanner.Possible},
		"null results":                {`{"results":null}`, scanner.Possible},
		"results of another tool":     {`{"results":[{"check_id":"a.b"}]}`, scanner.NotRecognized},
		"a gosec report":              {`{"Golang errors":{},"Issues":[{"severity":"HIGH","rule_id":"G201"}],"Stats":{}}`, scanner.NotRecognized},
		"a bandit report":             {`{"errors":[],"generated_at":"2026-10-14T00:00:00Z","metrics":{},"results":[{"test_id":"B101","issue_text":"x","filename":"a.py"}]}`, scanner.NotRecognized},
		"an npm audit report":         {`{"auditReportVersion":2,"vulnerabilities":{},"metadata":{}}`, scanner.NotRecognized},
		"a list of hadolint messages": {`[{"code":"DL3006","level":"warning","message":"x","file":"Dockerfile","line":1}]`, scanner.NotRecognized},
		"a SARIF log of another tool": {`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"other"}},"results":[]}]}`, scanner.NotRecognized},
		"a CycloneDX document":        {`{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`, scanner.NotRecognized},
		"an empty array":              {`[]`, scanner.NotRecognized},
		"an empty object":             {`{}`, scanner.NotRecognized},
		"null":                        {`null`, scanner.NotRecognized},
		"not JSON":                    {`not json`, scanner.NotRecognized},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, s.Recognize([]byte(tc.data)))
			assert.Equal(t, tc.want == scanner.Definite, s.DetectFormat([]byte(tc.data)), "DetectFormat is the definite grade")
		})
	}
}

func TestParseRefusesWhatIsNotThisTool(t *testing.T) {
	s := tfsec.NewScanner()
	for name, data := range map[string]string{
		"a gosec report":              `{"Golang errors":{},"Issues":[{"severity":"HIGH","rule_id":"G201"}],"Stats":{}}`,
		"a bandit report":             `{"errors":[],"generated_at":"2026-10-14T00:00:00Z","metrics":{},"results":[{"test_id":"B101","issue_text":"x","filename":"a.py"}]}`,
		"an npm audit report":         `{"auditReportVersion":2,"vulnerabilities":{},"metadata":{}}`,
		"a list of hadolint messages": `[{"code":"DL3006","level":"warning","message":"x","file":"Dockerfile","line":1}]`,
		"a SARIF log of another tool": `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"other"}},"results":[]}]}`,
		"a CycloneDX document":        `{"bomFormat":"CycloneDX","specVersion":"1.5","components":[]}`,
		"an empty array":              `[]`,
		"an empty object":             `{}`,
		"null":                        `null`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := s.Parse(context.Background(), []byte(data))
			require.ErrorIs(t, err, scanner.ErrUnrecognizedFormat)
			var fe *scanner.UnrecognizedFormatError
			require.ErrorAs(t, err, &fe)
			assert.Equal(t, "tfsec", fe.Scanner)
		})
	}
}

func TestParseAcceptsAnEmptyReport(t *testing.T) {
	s := tfsec.NewScanner()
	for name, data := range map[string]string{
		"empty results": `{"results":[]}`,
		"null results":  `{"results":null}`,
	} {
		t.Run(name, func(t *testing.T) {
			nr, err := s.Parse(context.Background(), []byte(data))
			require.NoError(t, err)
			assert.Empty(t, nr.Findings)
		})
	}
}

func TestParseCallsAnUnreadableReportMalformed(t *testing.T) {
	_, err := tfsec.NewScanner().Parse(context.Background(), []byte(`{"results":[{"rule_id":"a","long_id":"b","status":"oops"}]}`))
	require.ErrorIs(t, err, scanner.ErrMalformedReport)
	assert.NotErrorIs(t, err, scanner.ErrUnrecognizedFormat)
}
