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

func TestAGoVersionKeepsItsLeadingV(t *testing.T) {
	// OSV-Scanner writes Go versions without the "v" that Grype and Trivy
	// write. The same module version must give the same purl@version.
	cases := map[string]string{
		"bare version, package purl":      `"version":"1.3.1","ecosystem":"Go","purl":"pkg:golang/github.com/acme/lib@1.3.1"`,
		"bare version, no package purl":   `"version":"1.3.1","ecosystem":"Go"`,
		"version with v, package purl":    `"version":"v1.3.1","ecosystem":"Go","purl":"pkg:golang/github.com/acme/lib@v1.3.1"`,
		"version with v, no package purl": `"version":"v1.3.1","ecosystem":"Go"`,
	}
	for name, pkg := range cases {
		t.Run(name, func(t *testing.T) {
			data := []byte(`{"results":[{"source":{"path":"go.mod","type":"lockfile"},"packages":[{"package":{"name":"github.com/acme/lib",` + pkg + `},
				"vulnerabilities":[{"id":"GO-2026-0001","affected":[{"package":{"name":"github.com/acme/lib","ecosystem":"Go","purl":"pkg:golang/github.com/acme/lib"}}]}]}]}]}`)
			rep, err := osvscanner.NewScanner().Parse(context.Background(), data)
			require.NoError(t, err)
			require.Len(t, rep.Findings, 1)
			assert.Equal(t, "GO-2026-0001:pkg:golang/github.com/acme/lib@v1.3.1", rep.Findings[0].Fingerprint)
			require.Len(t, rep.Packages, 1)
			assert.Equal(t, "v1.3.1", rep.Packages[0].Version)
		})
	}
}

func TestOtherEcosystemsKeepTheirVersion(t *testing.T) {
	data := []byte(`{"results":[{"source":{"path":"package-lock.json","type":"lockfile"},"packages":[{"package":{"name":"lodash","version":"4.17.20","ecosystem":"npm","purl":"pkg:npm/lodash@4.17.20"},
		"vulnerabilities":[{"id":"GHSA-x"}]}]}]}`)
	rep, err := osvscanner.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, rep.Findings, 1)
	assert.Equal(t, "GHSA-x:pkg:npm/lodash@4.17.20", rep.Findings[0].Fingerprint)
}
