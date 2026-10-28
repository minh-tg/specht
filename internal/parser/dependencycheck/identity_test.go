package dependencycheck

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTwoFilesWithoutAPurlAndOneCVEAreTwoFindings(t *testing.T) {
	// Two binaries Dependency-Check matched by hash, so neither has a purl,
	// with the same CVE.
	data, err := os.ReadFile("testdata/no-purl-same-cve.json")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 2)
	assert.Equal(t, "CVE-2011-4969:/app/nginx-1.0.exe", rep.Findings[0].Fingerprint)
	assert.Equal(t, "CVE-2011-4969:/app/openssl.dll", rep.Findings[1].Fingerprint)
}

func TestAFileWithoutAPurlKeepsItsIdentityFromAnotherCheckout(t *testing.T) {
	// Dependency-Check writes the absolute path of each file it scanned.
	doc := func(path string) []byte {
		return []byte(`{"reportSchema":"1.1","dependencies":[{"fileName":"openssl.dll","filePath":"` + path + `",
			"vulnerabilities":[{"name":"CVE-2011-4969","severity":"MEDIUM"}]}]}`)
	}
	fingerprint := func(path string) string {
		rep, err := NewScanner().Parse(context.Background(), doc(path))
		require.NoError(t, err)
		require.Len(t, rep.Findings, 1)
		return rep.Findings[0].Fingerprint
	}
	assert.Equal(t, "CVE-2011-4969:vendor/openssl.dll", fingerprint("/src/vendor/openssl.dll"))
	assert.Equal(t, "CVE-2011-4969:vendor/openssl.dll", fingerprint("/home/runner/work/specht/specht/vendor/openssl.dll"))
	assert.Equal(t, "CVE-2011-4969:vendor/openssl.dll", fingerprint("/builds/x/1/vendor/openssl.dll"))
}

func TestTheScannerSaysItsIdentitiesChanged(t *testing.T) {
	assert.EqualValues(t, 2, NewScanner().Descriptor().FingerprintVersion)
	data, err := os.ReadFile("testdata/no-purl-same-cve.json")
	require.NoError(t, err)
	rep, err := NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	assert.EqualValues(t, 2, rep.FingerprintVersion)
}
