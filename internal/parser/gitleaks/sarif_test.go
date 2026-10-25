package gitleaks_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/gitleaks"
	"github.com/minh-tg/specht/internal/scanner"
)

func readSARIF(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	require.NoError(t, err)
	return data
}

func fingerprints(nr *domain.NormalizedReport) map[string]bool {
	out := map[string]bool{}
	for _, f := range nr.Findings {
		out[f.Fingerprint] = true
	}
	return out
}

func TestSARIFTwoSecretsOfOneRuleInOneFileAreTwoSecretFindings(t *testing.T) {
	nr, err := gitleaks.NewScanner().Parse(withKey(testKey), readSARIF(t, "gitleaks-two-secrets.sarif"))
	require.NoError(t, err)

	require.Len(t, nr.Findings, 2, "the generic SARIF adapter gave both the same fingerprint")
	assert.NotEqual(t, nr.Findings[0].Fingerprint, nr.Findings[1].Fingerprint)
	for _, f := range nr.Findings {
		assert.Equal(t, "secret", string(f.FindingKind))
		assert.Equal(t, domain.SeverityHigh, f.Severity)
		assert.True(t, strings.HasPrefix(f.Fingerprint, "secret:github-pat:cred.env:"), f.Fingerprint)
		assert.Equal(t, "secret", f.Extensions["identity_basis"])
		assert.Contains(t, f.Title, "GitHub Personal Access Token", "the title is the rule's description")
	}
	assert.Equal(t, "cred.env:1", nr.Findings[0].Location)
	assert.Equal(t, "cred.env:2", nr.Findings[1].Location)
}

func TestSARIFNeverCarriesTheCredential(t *testing.T) {
	nr, err := gitleaks.NewScanner().Parse(withKey(testKey), readSARIF(t, "gitleaks-two-secrets.sarif"))
	require.NoError(t, err)
	out, err := json.Marshal(nr)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "placeholder-credential")
}

func TestSARIFAndJSONGiveOneSecretOneIdentity(t *testing.T) {
	fromSARIF := parseDoc(t, withKey(testKey), string(readSARIF(t, "gitleaks-two-secrets.sarif")))
	fromJSON := parseDoc(t, withKey(testKey), list(
		leak("github-pat", "cred.env", "placeholder-credential-one", 1, ""),
		leak("github-pat", "cred.env", "placeholder-credential-two", 2, ""),
	))
	assert.Equal(t, fingerprints(fromJSON), fingerprints(fromSARIF),
		"a report uploaded in either format updates the same findings")
}

func TestSARIFTheSameSecretInManyCommitsIsOneFinding(t *testing.T) {
	nr, err := gitleaks.NewScanner().Parse(withKey(testKey), readSARIF(t, "gitleaks-history.sarif"))
	require.NoError(t, err)

	require.Len(t, nr.Findings, 3, "one secret in two commits, another in one")
	assert.Len(t, fingerprints(nr), 2,
		"the generic SARIF adapter hashed the commit, author and date, so one secret became one finding per commit")
}

func TestSARIFARotatedSecretIsANewFinding(t *testing.T) {
	data := readSARIF(t, "gitleaks-two-secrets.sarif")
	rotated := strings.ReplaceAll(string(data), "placeholder-credential-two", "placeholder-credential-three")
	before := parseDoc(t, withKey(testKey), string(data))
	after := parseDoc(t, withKey(testKey), rotated)

	assert.Equal(t, before.Findings[0].Fingerprint, after.Findings[0].Fingerprint)
	assert.NotEqual(t, before.Findings[1].Fingerprint, after.Findings[1].Fingerprint)
}

func TestSARIFNeedsTheKeyToHashACredential(t *testing.T) {
	_, err := gitleaks.NewScanner().Parse(context.Background(), readSARIF(t, "gitleaks-two-secrets.sarif"))
	require.ErrorIs(t, err, scanner.ErrFingerprintKeyRequired)
}

// A report written with --redact has REDACTED where the credential was. Each
// leak is still told apart by its position, and no key is needed.
func TestSARIFRedactedReportKeepsLeaksApart(t *testing.T) {
	nr, err := gitleaks.NewScanner().Parse(context.Background(), readSARIF(t, "gitleaks-redacted.sarif"))
	require.NoError(t, err)

	require.Len(t, nr.Findings, 2)
	assert.NotEqual(t, nr.Findings[0].Fingerprint, nr.Findings[1].Fingerprint)
	for _, f := range nr.Findings {
		assert.Equal(t, "fingerprint", f.Extensions["identity_basis"])
	}
}

func TestSARIFEvidenceIsRedactedAndStillParses(t *testing.T) {
	data := readSARIF(t, "gitleaks-two-secrets.sarif")
	out, err := gitleaks.NewScanner().RedactRaw(data)
	require.NoError(t, err)
	assert.NotContains(t, string(out), "placeholder-credential")
	assert.Contains(t, string(out), "github-pat", "provenance is kept")

	again, err := gitleaks.NewScanner().Parse(context.Background(), out)
	require.NoError(t, err)
	require.Len(t, again.Findings, 2)
	assert.NotEqual(t, again.Findings[0].Fingerprint, again.Findings[1].Fingerprint,
		"stored evidence parsed again still tells the leaks apart")
}

func TestSARIFRecognition(t *testing.T) {
	s := gitleaks.NewScanner()
	for name, tc := range map[string]struct {
		data string
		want scanner.Recognition
	}{
		"a Gitleaks log":        {string(readSARIF(t, "gitleaks-two-secrets.sarif")), scanner.Definite},
		"a clean Gitleaks log":  {`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[]}]}`, scanner.Definite},
		"a log of another tool": {`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"codeql"}},"results":[]}]}`, scanner.NotRecognized},
		"a log that mixes tools": {`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gitleaks"}},"results":[]},` +
			`{"tool":{"driver":{"name":"codeql"}},"results":[]}]}`, scanner.NotRecognized},
		"a log without runs": {`{"version":"2.1.0","runs":[]}`, scanner.NotRecognized},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, s.Recognize([]byte(tc.data)))
		})
	}
}
