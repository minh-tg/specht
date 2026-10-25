package semgrep

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSARIFExaminedKeysAreTheRuleList(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS","rules":[{"id":"a.b"},{"id":"c.d"}]}},"results":[]}]}`
	nr, err := NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	assert.Equal(t, []string{"rule:sast:a.b", "rule:sast:c.d"}, nr.ExaminedKeys)
}

func TestSARIFFailedRunExaminesNothing(t *testing.T) {
	doc := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS","rules":[{"id":"a.b"}]}},"invocations":[{"executionSuccessful":false}],"results":[]}]}`
	nr, err := NewScanner().Parse(context.Background(), []byte(doc))
	require.NoError(t, err)
	assert.Empty(t, nr.ExaminedKeys)
}

func TestNativeJSONExaminesNothing(t *testing.T) {
	data, err := os.ReadFile("testdata/semgrep-native.json")
	require.NoError(t, err)
	nr, err := NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	assert.Empty(t, nr.ExaminedKeys, "the native format lists no rules")
}
