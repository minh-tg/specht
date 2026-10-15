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
	redacted := NewScanner().RedactRaw(data)
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

func TestRedactRawPassthrough(t *testing.T) {
	s := NewScanner()
	assert.Equal(t, []byte(`not json`), []byte(s.RedactRaw([]byte(`not json`))))
	assert.True(t, strings.HasPrefix(string(s.RedactRaw([]byte(`[]`))), "["))
}

func TestDetectFormat(t *testing.T) {
	data, err := os.ReadFile("testdata/gitleaks.json")
	require.NoError(t, err)
	assert.True(t, NewScanner().DetectFormat(data))
	assert.False(t, NewScanner().DetectFormat([]byte(`[{"Target":"x"}]`)))
}
