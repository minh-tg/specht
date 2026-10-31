package gitleaks_test

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
)

// Gitleaks 8.30.1 in directory mode writes File, and the SARIF artifact uri, as
// the path it was given. Run on an absolute path (what a CI job does with
// "$CI_PROJECT_DIR" or "$PWD") that puts the checkout directory into the file,
// and so into the identity.
func TestADirectoryScanKeepsItsIdentityFromAnotherCheckout(t *testing.T) {
	for _, format := range []string{"json", "sarif"} {
		t.Run(format, func(t *testing.T) {
			data, err := os.ReadFile("testdata/gitleaks-dir-mode." + format)
			require.NoError(t, err)
			parse := func(root string) *domain.NormalizedReport {
				doc := strings.ReplaceAll(string(data), `/src/`, root)
				return parseDoc(t, withKey(testKey), doc)
			}
			want := parse("")
			require.Len(t, want.Findings, 1)
			assert.Equal(t, "config/app.env", want.Findings[0].CodeLocation.File)

			for _, root := range []string{"/src/", "/github/workspace/", "/builds/x/1/", "/home/runner/work/api/api/"} {
				got := parse(root)
				require.Len(t, got.Findings, 1, root)
				assert.Equal(t, want.Findings[0].Fingerprint, got.Findings[0].Fingerprint, root)
				assert.Equal(t, "config/app.env", got.Findings[0].CodeLocation.File, root)
			}
		})
	}
}

func TestTheSameSecretInJSONAndSARIFDirectoryScansIsOneFinding(t *testing.T) {
	j, err := os.ReadFile("testdata/gitleaks-dir-mode.json")
	require.NoError(t, err)
	s, err := os.ReadFile("testdata/gitleaks-dir-mode.sarif")
	require.NoError(t, err)
	a := parseDoc(t, withKey(testKey), string(j))
	b := parseDoc(t, withKey(testKey), string(s))
	require.Len(t, a.Findings, 1)
	require.Len(t, b.Findings, 1)
	assert.Equal(t, a.Findings[0].Fingerprint, b.Findings[0].Fingerprint)
}

func TestARedactedDirectoryScanKeepsItsIdentityFromAnotherCheckout(t *testing.T) {
	// --redact leaves no credential to hash, so the identity is Gitleaks' own
	// fingerprint, which holds the path the scan was given.
	data, err := os.ReadFile("testdata/gitleaks-dir-mode.json")
	require.NoError(t, err)
	redacted := strings.ReplaceAll(string(data), "xoxb-placeholder-secret-value-01", "REDACTED")
	want := parseDoc(t, withKey(testKey), strings.ReplaceAll(redacted, `/src/`, ""))
	got := parseDoc(t, withKey(testKey), strings.ReplaceAll(redacted, `/src/`, "/builds/x/1/"))
	require.Len(t, want.Findings, 1)
	require.Len(t, got.Findings, 1)
	assert.Equal(t, "fingerprint", got.Findings[0].Extensions["identity_basis"])
	assert.Equal(t, want.Findings[0].Fingerprint, got.Findings[0].Fingerprint)
}
