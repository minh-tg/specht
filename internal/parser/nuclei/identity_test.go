package nuclei

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTwoMatchersOfOneTemplateAtOneURLAreTwoFindings(t *testing.T) {
	// Nuclei 3.11.1, one template with a matcher per missing header, run
	// against one URL that lacks both headers.
	data, err := os.ReadFile("testdata/nuclei-two-matchers.jsonl")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 2)

	assert.Equal(t, "dast:missing-headers-probe:x-frame-options:http://127.0.0.1:18099/", rep.Findings[0].Fingerprint)
	assert.Equal(t, "dast:missing-headers-probe:content-security-policy:http://127.0.0.1:18099/", rep.Findings[1].Fingerprint)
	assert.Equal(t, "content-security-policy", rep.Findings[1].Extensions["matcher_name"])
}

func TestAnEventWithoutAMatcherNameKeepsItsIdentity(t *testing.T) {
	rep, err := NewScanner().Parse(context.Background(), []byte(`{"template-id":"t","host":"https://h.example.com","matched-at":"https://h.example.com/a"}`))
	require.NoError(t, err)
	require.Len(t, rep.Findings, 1)
	assert.Equal(t, "dast:t:https://h.example.com/a", rep.Findings[0].Fingerprint)
}

func TestTheScannerSaysItsIdentitiesChanged(t *testing.T) {
	assert.EqualValues(t, 2, NewScanner().Descriptor().FingerprintVersion)
	rep, err := NewScanner().Parse(context.Background(), []byte(`{"template-id":"t","host":"https://h.example.com"}`))
	require.NoError(t, err)
	assert.EqualValues(t, 2, rep.FingerprintVersion)
}
