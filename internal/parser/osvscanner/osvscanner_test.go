package osvscanner_test

import (
	"context"
	"os"
	"testing"

	"github.com/minh-tg/specht/internal/domain"

	"github.com/minh-tg/specht/internal/parser/osvscanner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestName(t *testing.T) {
	s := osvscanner.NewScanner()
	assert.Equal(t, "osv-scanner", s.Descriptor().Name)
}

func TestDetect_ValidInput(t *testing.T) {
	s := osvscanner.NewScanner()
	data, err := os.ReadFile("testdata/go-scan.json")
	require.NoError(t, err)
	assert.True(t, s.DetectFormat(data))
}

func TestDetect_InvalidInput(t *testing.T) {
	s := osvscanner.NewScanner()
	assert.False(t, s.DetectFormat([]byte(`{}`)))
	assert.False(t, s.DetectFormat([]byte(`not json`)))
}

func TestParse_GoScan(t *testing.T) {
	s := osvscanner.NewScanner()
	data, err := os.ReadFile("testdata/go-scan.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	assert.Equal(t, "osv-scanner", osvscanner.NewScanner().Descriptor().Name)
	require.NotNil(t, report.Target)
	assert.Equal(t, "package", report.Target.Kind)
	assert.Equal(t, "lockfile", report.ScanScope.Ext["osv_source_type"])
	assert.Len(t, report.Findings, 1)

	finding := report.Findings[0]

	expectedFP := "GHSA-c3h9-896r-86jm:pkg:golang/github.com/gogo/protobuf"
	assert.Equal(t, expectedFP, finding.Fingerprint)
	assert.Equal(t, "sca", finding.FindingKind)
	assert.Equal(t, 3, int(finding.Severity)) // high
	assert.Equal(t, 9.3, finding.Score)

	// Aliases promoted from metadata to struct field
	require.Len(t, finding.Aliases, 1)
	assert.Equal(t, "CVE-2021-3121", finding.Aliases[0])

	// Reachability is a typed hint (state/evidence/source), not a raw bool.
	require.NotNil(t, finding.Reachability)
	assert.Equal(t, "reachable", string(finding.Reachability.State))
	assert.Equal(t, "osv", finding.Reachability.Source)

	// CVSS extracted from severity array
	require.NotNil(t, finding.CVSS)
	assert.Equal(t, "4.0", finding.CVSS.Version)
	assert.Equal(t, 9.3, finding.CVSS.Score)
	assert.Contains(t, finding.CVSS.Vector, "CVSS:4.0")

	// Fix populated from fix version
	require.NotNil(t, finding.Fix)
	assert.Equal(t, "1.3.2", finding.Fix.Summary)

	// Observation payload lands in Extensions.
	assert.Equal(t, []string{"CVE-2021-3121"}, finding.Extensions["aliases"])

	// The location names the affected package and where it was observed.
	assert.Equal(t, "github.com/gogo/protobuf 1.3.1 in /home/user/project/go.mod", finding.Location)
}

func TestParseCVSSInfo(t *testing.T) {
	s := osvscanner.NewScanner()
	data, err := os.ReadFile("testdata/go-scan.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, report.Findings, 1)

	finding := report.Findings[0]
	require.NotNil(t, finding.CVSS)
	assert.Equal(t, "4.0", finding.CVSS.Version)
	assert.True(t, finding.CVSS.Score > 0)
}

func TestParse_GoFullScan(t *testing.T) {
	s := osvscanner.NewScanner()
	data, err := os.ReadFile("testdata/go-full.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	// Only the vulnerable subset surfaces as findings.
	require.Len(t, report.Findings, 12)

	// The full lockfile contents are captured, vulnerable or not.
	require.GreaterOrEqual(t, len(report.Packages), 100)
	require.Greater(t, len(report.Packages), len(report.Findings))

	// A clearly non-vulnerable module is present with its manifest path.
	// (github.com/gin-gonic/gin is actually vulnerable in this fixture —
	// GHSA-5zsk-r65m-s884 — so cobra, whose vulnerabilities are empty, is
	// the honest non-vulnerable probe.)
	found := false
	for _, p := range report.Packages {
		if p.Name == "github.com/spf13/cobra" {
			found = true
			assert.Equal(t, "Go", p.Ecosystem)
			assert.NotEmpty(t, p.Version)
			assert.Equal(t, "/home/ci/app/go.mod", p.ManifestPath)
			assert.Contains(t, p.PURL, "pkg:golang/github.com/spf13/cobra@")
			assert.NotContains(t, p.PURL, "?")
		}
	}
	assert.True(t, found, "non-vulnerable module github.com/spf13/cobra missing from inventory")

	// Every finding maps to a captured package. osv findings identify
	// packages by name only: finding purls are built from the OSV
	// affected.package record, which carries no version (see TestParse_GoScan),
	// while the inventory records purl@version. Compare at name level.
	findingPURLs := map[string]bool{}
	for _, f := range report.Findings {
		for _, d := range f.Dimensions {
			if d.Key == "purl" {
				findingPURLs[domain.NormalizePURL(d.Value)] = true
			}
		}
	}
	inventory := map[string]bool{}
	for _, p := range report.Packages {
		pkgType, name, _ := domain.SplitPURL(p.PURL)
		inventory["pkg:"+pkgType+"/"+name] = true
	}
	for purl := range findingPURLs {
		pkgType, name, _ := domain.SplitPURL(purl)
		key := purl
		if name != "" {
			key = "pkg:" + pkgType + "/" + name
		}
		assert.True(t, inventory[key], "finding purl %s not in inventory", purl)
	}
}

func TestParse_InvalidJSON(t *testing.T) {
	s := osvscanner.NewScanner()
	_, err := s.Parse(context.Background(), []byte(`not json`))
	assert.Error(t, err)
}

func TestParse_MissingAffectedRecordUsesPackageInventory(t *testing.T) {
	data := []byte(`{"results":[{"source":{"path":"go.mod","type":"lockfile"},"packages":[{"package":{"name":"example.com/app","version":"v1.0.0","ecosystem":"Go","purl":"pkg:golang/example.com/app@v1.0.0"},"vulnerabilities":[{"id":"GO-2026-0001","summary":"missing affected record"}]}]}]}`)
	report, err := osvscanner.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, report.Findings, 1)
	assert.Equal(t, "GO-2026-0001:pkg:golang/example.com/app@v1.0.0", report.Findings[0].Fingerprint)
}

func TestParse_AffectedPackageSelection(t *testing.T) {
	cases := []struct {
		name     string
		affected string
		purl     string
		fixed    string
	}{
		{"legacy object", `{"package":{"name":"lodash","ecosystem":"npm","purl":"pkg:npm/lodash"},"ranges":[{"events":[{"fixed":"4.17.21"}]}]}`, "pkg:npm/lodash", "4.17.21"},
		{"matching package is not first", `[{"package":{"name":"lodash.trim","ecosystem":"npm","purl":"pkg:npm/lodash.trim"},"ranges":[{"events":[{"fixed":"4.5.1"}]}]},{"package":{"name":"lodash","ecosystem":"npm","purl":"pkg:npm/lodash"},"ranges":[{"events":[{"fixed":"4.17.21"}]}]}]`, "pkg:npm/lodash", "4.17.21"},
		{"same name in another ecosystem", `[{"package":{"name":"lodash","ecosystem":"RubyGems","purl":"pkg:gem/lodash"},"ranges":[{"events":[{"fixed":"1.0.0"}]}]},{"package":{"name":"lodash","ecosystem":"npm","purl":"pkg:npm/lodash"},"ranges":[{"events":[{"fixed":"4.17.21"}]}]}]`, "pkg:npm/lodash", "4.17.21"},
		{"no matching package", `[{"package":{"name":"lodash.trim","ecosystem":"npm","purl":"pkg:npm/lodash.trim"}}]`, "pkg:npm/lodash@4.17.20", ""},
		{"package-less advisory", `[{"ranges":[{"events":[{"fixed":"99.0.0"}]}]}]`, "pkg:npm/lodash@4.17.20", ""},
		{"empty list", `[]`, "pkg:npm/lodash@4.17.20", ""},
		{"null", `null`, "pkg:npm/lodash@4.17.20", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data := []byte(`{"results":[{"source":{"path":"package-lock.json","type":"lockfile"},"packages":[{"package":{"name":"lodash","version":"4.17.20","ecosystem":"npm","purl":"pkg:npm/lodash@4.17.20"},"vulnerabilities":[{"id":"GHSA-test","affected":` + tc.affected + `}]}]}]}`)
			report, err := osvscanner.NewScanner().Parse(context.Background(), data)
			require.NoError(t, err)
			require.Len(t, report.Findings, 1)
			f := report.Findings[0]
			assert.Equal(t, "GHSA-test:"+tc.purl, f.Fingerprint)
			assert.Contains(t, f.Dimensions, domain.Dimension{Key: domain.DimPackageName, Value: "lodash"})
			if tc.fixed == "" {
				assert.Nil(t, f.Fix, "unrelated package fixes must not leak into this finding")
			} else {
				require.NotNil(t, f.Fix)
				assert.Equal(t, tc.fixed, f.Fix.Summary)
			}
		})
	}
}

func TestParse_RejectsMalformedAffectedRecords(t *testing.T) {
	for _, affected := range []string{`"bad"`, `7`, `[7]`} {
		t.Run(affected, func(t *testing.T) {
			data := []byte(`{"results":[{"packages":[{"vulnerabilities":[{"affected":` + affected + `}]}]}]}`)
			_, err := osvscanner.NewScanner().Parse(context.Background(), data)
			require.Error(t, err)
		})
	}
}

func TestParse_MultipleResultsPreservesLastTargetAndInventory(t *testing.T) {
	data := []byte(`{"results":[{"source":{"path":"repo/go.mod","type":"lockfile"},"packages":[{"package":{"name":"acme/first","version":"1.2.3","ecosystem":"Go","purl":"pkg:golang/acme/first@1.2.3"},"vulnerabilities":[{"id":"GO-2026-0001","summary":"first issue"}]}]},{"source":{"path":"service/package-lock.json","type":"repository"},"packages":[{"package":{"name":"last","version":"4.5.6","ecosystem":"npm","purl":"pkg:npm/last@4.5.6"},"vulnerabilities":[{"id":"GHSA-2026-0002","summary":"last issue"}]}]}]}`)
	report, err := osvscanner.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.NotNil(t, report.Target)
	assert.Equal(t, "repo", report.Target.Kind)
	assert.Equal(t, "service/package-lock.json", report.Target.Identifier)
	assert.Equal(t, "repository", report.ScanScope.Ext["osv_source_type"])
	assert.Equal(t, "service/package-lock.json", report.ScanScope.Ext["osv_source_path"])

	require.Len(t, report.Packages, 2, "inventory must include packages from every result")
	packages := make(map[string]string, len(report.Packages))
	for _, pkg := range report.Packages {
		packages[pkg.Name] = pkg.ManifestPath
	}
	assert.Equal(t, map[string]string{
		"acme/first": "repo/go.mod",
		"last":       "service/package-lock.json",
	}, packages)

	require.Len(t, report.Findings, 2)
	wantFingerprints := []string{
		"GO-2026-0001:pkg:golang/acme/first@1.2.3",
		"GHSA-2026-0002:pkg:npm/last@4.5.6",
	}
	gotFingerprints := make([]string, len(report.Findings))
	for i, finding := range report.Findings {
		gotFingerprints[i] = finding.Fingerprint
	}
	assert.Equal(t, wantFingerprints, gotFingerprints)

	repeated, err := osvscanner.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, repeated.Findings, len(report.Findings))
	for i := range report.Findings {
		assert.Equal(t, report.Findings[i].Fingerprint, repeated.Findings[i].Fingerprint)
	}
}

func TestTargetKindForSource(t *testing.T) {
	for _, tc := range []struct {
		sourceType string
		want       string
	}{
		{"lockfile", "package"},
		{"sbom", "package"},
		{"repository", "repo"},
		{"git", "repo"},
		{"image", "container_image"},
		{"filesystem", "filesystem"},
		{"iac", "iac_stack"},
		{"future-source", "package"},
	} {
		t.Run(tc.sourceType, func(t *testing.T) {
			data := []byte(`{"results":[{"source":{"type":"` + tc.sourceType + `","path":"go.mod"}}]}`)
			report, err := osvscanner.NewScanner().Parse(context.Background(), data)
			require.NoError(t, err)
			require.NotNil(t, report.Target)
			assert.Equal(t, tc.want, report.Target.Kind)
			assert.Equal(t, tc.sourceType, report.ScanScope.Ext["osv_source_type"])
		})
	}
}

func TestFindingKind(t *testing.T) {
	s := osvscanner.NewScanner()
	assert.Equal(t, "sca", string(s.Descriptor().FindingKinds[0]))
}
