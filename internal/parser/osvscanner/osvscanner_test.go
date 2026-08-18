package osvscanner_test

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/parser/osvscanner"
	"github.com/xMinhx/specht/internal/scanner"
)

func TestName(t *testing.T) {
	s := osvscanner.NewScanner()
	assert.Equal(t, "osv-scanner", s.Name())
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

	assert.Equal(t, "osv-scanner", report.ToolName)
	require.NotNil(t, report.Target)
	assert.Len(t, report.Findings, 1)

	finding := report.Findings[0]

	expectedFP := "GHSA-c3h9-896r-86jm:pkg:golang/github.com/gogo/protobuf"
	assert.Equal(t, expectedFP, finding.Fingerprint)
	assert.Equal(t, "sca", finding.FindingKind)
	assert.Equal(t, scanner.SeverityHigh, finding.Severity)
	assert.Equal(t, 9.3, finding.Score)

	// Aliases promoted from metadata to struct field
	require.Len(t, finding.Aliases, 1)
	assert.Equal(t, "CVE-2021-3121", finding.Aliases[0])

	// Reachability promoted from display to struct field
	require.NotNil(t, finding.Reachability)
	assert.True(t, *finding.Reachability)

	// CVSS extracted from severity array
	require.NotNil(t, finding.CVSS)
	assert.Equal(t, "4.0", finding.CVSS.Version)
	assert.Equal(t, 9.3, finding.CVSS.Score)
	assert.Contains(t, finding.CVSS.Vector, "CVSS:4.0")

	// Fix populated from fix version
	require.NotNil(t, finding.Fix)
	assert.Equal(t, "1.3.2", finding.Fix.Summary)

	// Legacy display/meta still populated for backward compat
	reachable, ok := finding.Display["reachable"]
	assert.True(t, ok)
	assert.Equal(t, true, reachable)
	assert.Equal(t, []string{"CVE-2021-3121"}, finding.Metadata["aliases"])
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
				findingPURLs[scanner.NormalizePURL(d.Value)] = true
			}
		}
	}
	inventory := map[string]bool{}
	for _, p := range report.Packages {
		pkgType, name, _ := scanner.SplitPURL(p.PURL)
		inventory["pkg:"+pkgType+"/"+name] = true
	}
	for purl := range findingPURLs {
		pkgType, name, _ := scanner.SplitPURL(purl)
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

func TestFindingKind(t *testing.T) {
	s := osvscanner.NewScanner()
	assert.Equal(t, "sca", s.FindingKind())
}
