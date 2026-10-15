package checkov_test

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/checkov"
	"github.com/minh-tg/specht/internal/scanner"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return data
}

// Checkov writes one report per framework. A directory with Terraform, Kubernetes and a Dockerfile
// gives a JSON array, which is what checkov -d . produces in most real projects.
func TestMultiFrameworkReport(t *testing.T) {
	s := checkov.NewScanner()
	data := readTestdata(t, "checkov-multi.json")
	require.Equal(t, scanner.Definite, s.Recognize(data))

	nr, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	assert.Len(t, nr.Findings, 6, "two failed checks from each of three frameworks")
	byType := map[string]int{}
	seen := map[string]bool{}
	for _, f := range nr.Findings {
		byType[f.Extensions["check_type"].(string)]++
		assert.False(t, seen[f.Fingerprint], "each finding keeps its own identity")
		seen[f.Fingerprint] = true
		assert.Equal(t, "iac", f.FindingKind)
	}
	assert.Equal(t, map[string]int{"dockerfile": 2, "kubernetes": 2, "terraform": 2}, byType)

	assert.Equal(t, domain.ScanTypeIaC, nr.ScanType)
	require.NotNil(t, nr.Target)
	assert.Equal(t, "iac", nr.Target.Kind, "one target kind cannot name three frameworks")
	require.NotNil(t, nr.ScanScope)
	assert.Equal(t, "dockerfile,kubernetes,terraform", nr.ScanScope.Ext["checkov_frameworks"])
}

// A list holding one framework is the same scan as that framework's bare report.
func TestAListOfOneFrameworkEqualsTheBareReport(t *testing.T) {
	s := checkov.NewScanner()
	bare := readTestdata(t, "checkov-terraform.json")
	var asObject json.RawMessage = bare
	listed, err := json.Marshal([]json.RawMessage{asObject})
	require.NoError(t, err)

	a, err := s.Parse(context.Background(), bare)
	require.NoError(t, err)
	b, err := s.Parse(context.Background(), listed)
	require.NoError(t, err)

	require.Equal(t, len(a.Findings), len(b.Findings))
	for i := range a.Findings {
		assert.Equal(t, a.Findings[i].Fingerprint, b.Findings[i].Fingerprint)
	}
	assert.Equal(t, a.Target, b.Target)
	assert.Nil(t, b.ScanScope, "a single framework leaves the scan scope as it always was")
}

func TestSingleFrameworkReportsAreUnchanged(t *testing.T) {
	nr, err := checkov.NewScanner().Parse(context.Background(), readTestdata(t, "checkov-terraform.json"))
	require.NoError(t, err)
	require.NotNil(t, nr.Target)
	assert.Equal(t, "terraform", nr.Target.Kind)
	assert.Nil(t, nr.ScanScope)
}

func TestListRecognition(t *testing.T) {
	s := checkov.NewScanner()
	for name, tc := range map[string]struct {
		doc  string
		want scanner.Recognition
	}{
		"a list of framework reports":        {`[{"check_type":"terraform","results":{}},{"check_type":"kubernetes","results":{}}]`, scanner.Definite},
		"a list of one":                      {`[{"check_type":"terraform","results":{}}]`, scanner.Definite},
		"a list with an element that is not": {`[{"check_type":"terraform","results":{}},{"foo":1}]`, scanner.NotRecognized},
		"an empty list":                      {`[]`, scanner.NotRecognized},
		"a list of other tools' findings":    {`[{"RuleID":"a","File":"b"}]`, scanner.NotRecognized},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, s.Recognize([]byte(tc.doc)))
		})
	}
}

func TestListWithAnUnreadableFrameworkIsMalformed(t *testing.T) {
	_, err := checkov.NewScanner().Parse(context.Background(),
		[]byte(`[{"check_type":"terraform","results":{}},{"check_type":"kubernetes","results":"oops"}]`))
	require.ErrorIs(t, err, scanner.ErrMalformedReport)
}

func TestParsingErrorsAreNotedOnTheReport(t *testing.T) {
	doc := `[{"check_type":"terraform","results":{"parsing_errors":["bad.tf"]},"summary":{"parsing_errors":1}},` +
		`{"check_type":"kubernetes","results":{},"summary":{"parsing_errors":0}}]`
	nr, err := checkov.NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	require.NotNil(t, nr.ScanScope)
	assert.Equal(t, "1", nr.ScanScope.Ext["checkov_parsing_errors"], "files Checkov could not read are missing from the results")
}
