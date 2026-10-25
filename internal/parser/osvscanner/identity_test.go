package osvscanner_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/osvscanner"
)

func TestTwoInstalledVersionsOfOnePackageAreTwoFindings(t *testing.T) {
	// OSV-Scanner on two lockfiles, lodash 4.17.20 in one and 4.17.15 in the
	// other, with the same advisory. The advisory's purl has no version.
	data, err := os.ReadFile("testdata/two-lockfiles.json")
	require.NoError(t, err)
	rep, err := osvscanner.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)

	byFingerprint := map[string]domain.NormalizedFinding{}
	for _, f := range rep.Findings {
		byFingerprint[f.Fingerprint] = f
	}
	newer, ok := byFingerprint["GHSA-29mw-wpgm-hmr9:pkg:npm/lodash@4.17.20"]
	require.True(t, ok, "fingerprints: %v", byFingerprint)
	_, ok = byFingerprint["GHSA-29mw-wpgm-hmr9:pkg:npm/lodash@4.17.15"]
	require.True(t, ok)
	assert.Contains(t, newer.Dimensions, domain.Dimension{Key: domain.DimPURL, Value: "pkg:npm/lodash@4.17.20"})
}

func TestTheAdvisoryGivesThePurlTypeWhenThePackageHasNoPurl(t *testing.T) {
	// "Go" is not a purl type; the advisory says golang.
	data := []byte(`{"results":[{"source":{"path":"go.mod","type":"lockfile"},"packages":[{"package":{"name":"github.com/acme/lib","version":"v1.2.0","ecosystem":"Go"},
		"vulnerabilities":[{"id":"GO-2026-0001","affected":[{"package":{"name":"github.com/acme/lib","ecosystem":"Go","purl":"pkg:golang/github.com/acme/lib"}}]}]}]}]}`)
	rep, err := osvscanner.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 1)
	assert.Equal(t, "GO-2026-0001:pkg:golang/github.com/acme/lib@v1.2.0", rep.Findings[0].Fingerprint)
}

func TestAScopedPackageKeepsItsScope(t *testing.T) {
	data := []byte(`{"results":[{"source":{"path":"package-lock.json","type":"lockfile"},"packages":[{"package":{"name":"@angular/core","version":"17.0.0","ecosystem":"npm"},
		"vulnerabilities":[{"id":"GHSA-x","affected":[{"package":{"name":"@angular/core","ecosystem":"npm","purl":"pkg:npm/%40angular/core"}}]}]}]}]}`)
	rep, err := osvscanner.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 1)
	assert.Equal(t, "GHSA-x:pkg:npm/%40angular/core@17.0.0", rep.Findings[0].Fingerprint)
}

func TestTheScannerSaysItsIdentitiesChanged(t *testing.T) {
	assert.EqualValues(t, 2, osvscanner.NewScanner().Descriptor().FingerprintVersion)
	rep, err := osvscanner.NewScanner().Parse(context.Background(), []byte(`{"results":[]}`))
	require.NoError(t, err)
	assert.EqualValues(t, 2, rep.FingerprintVersion)
}
