package trivy_test

import (
	"context"
	"os"
	"testing"

	"github.com/minh-tg/specht/internal/domain"

	"github.com/minh-tg/specht/internal/parser/trivy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestName(t *testing.T) {
	s := trivy.NewScanner()
	assert.Equal(t, "trivy", s.Descriptor().Name)
}

func TestDetect_ValidInput(t *testing.T) {
	s := trivy.NewScanner()
	data, err := os.ReadFile("testdata/alpine-scan.json")
	require.NoError(t, err)
	assert.True(t, s.DetectFormat(data))
}

func TestDetect_InvalidInput(t *testing.T) {
	s := trivy.NewScanner()
	assert.False(t, s.DetectFormat([]byte(`{}`)))
	assert.False(t, s.DetectFormat([]byte(`not json`)))
}

func TestParse_AlpineScan(t *testing.T) {
	s := trivy.NewScanner()
	data, err := os.ReadFile("testdata/alpine-scan.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	require.NotNil(t, report.Target)
	assert.Equal(t, "alpine:3.20 (alpine 3.20.3)", report.Target.Identifier)
	require.Len(t, report.Findings, 2)

	tests := []struct {
		name         string
		fingerprint  string
		severity     domain.Severity
		score        float64
		findingKind  string
		fixedVersion string
	}{
		{
			name:         "first finding should be CVE-2024-9143",
			fingerprint:  "CVE-2024-9143:pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=aarch64&distro=3.20.3",
			severity:     domain.SeverityLow,
			score:        4.0,
			findingKind:  "sca",
			fixedVersion: "3.3.2-r1",
		},
		{
			name:         "second finding should be CVE-2024-8888",
			fingerprint:  "CVE-2024-8888:pkg:apk/alpine/libssl3@3.3.2-r0?arch=aarch64&distro=3.20.3",
			severity:     domain.SeverityHigh,
			score:        6.0,
			findingKind:  "sca",
			fixedVersion: "3.3.2-r1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			found := false
			for _, f := range report.Findings {
				if f.Fingerprint == tt.fingerprint {
					found = true
					assert.Equal(t, tt.severity, f.Severity)
					assert.Equal(t, tt.findingKind, f.FindingKind)
					assert.Equal(t, tt.score, f.Score)
					break
				}
			}
			assert.True(t, found, "finding with fingerprint %q not found", tt.fingerprint)
		})
	}
}

func TestParse_EmptyScan(t *testing.T) {
	s := trivy.NewScanner()
	data, err := os.ReadFile("testdata/empty-scan.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	assert.Empty(t, report.Findings)
}

func TestParse_CurrentCleanEnvelope(t *testing.T) {
	report, err := trivy.NewScanner().Parse(context.Background(), []byte(`{"SchemaVersion":2,"ArtifactName":"alpine:3.20","ArtifactType":"container_image","Results":null}`))
	require.NoError(t, err)
	assert.Empty(t, report.Findings)
	require.NotNil(t, report.Target)
	assert.Equal(t, "alpine:3.20", report.Target.Identifier)
}

func TestParse_LegacyArrayEnvelope(t *testing.T) {
	report, err := trivy.NewScanner().Parse(context.Background(), []byte(`[{"Target":"alpine:3.20","Class":"os-pkgs","Type":"alpine"}]`))
	require.NoError(t, err)
	require.NotNil(t, report.Target)
	assert.Equal(t, "alpine:3.20", report.Target.Identifier)
}

func TestParse_AlpineFullScan(t *testing.T) {
	s := trivy.NewScanner()
	data, err := os.ReadFile("testdata/alpine-full.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	// Only the vulnerable subset surfaces as findings.
	require.Len(t, report.Findings, 8)

	// The full package tree is captured, not just vulnerable packages.
	require.GreaterOrEqual(t, len(report.Packages), 100)
	require.Greater(t, len(report.Packages), len(report.Findings))

	// A vulnerable package is present, with qualifiers stripped from its purl
	// so it can be matched against findings by purl@version.
	vulnRef, ok := packageByPURL(report.Packages, "pkg:apk/alpine/libcrypto3@3.3.2-r0")
	require.True(t, ok, "vulnerable package libcrypto3 missing from inventory")
	assert.Equal(t, "alpine", vulnRef.Ecosystem)
	assert.Equal(t, "libcrypto3", vulnRef.Name)
	assert.Equal(t, "3.3.2-r0", vulnRef.Version)

	// A package with no finding is captured too.
	cleanRef, ok := packageByPURL(report.Packages, "pkg:apk/alpine/ncurses@6.4_p20240414-r0")
	require.True(t, ok, "non-vulnerable package ncurses missing from inventory")
	assert.Equal(t, "ncurses", cleanRef.Name)

	// Vulnerable packages are a strict subset of the inventory: every finding
	// references a captured package, but findings do not cover the inventory.
	vulnPURLs := map[string]bool{}
	for _, p := range report.Packages {
		vulnPURLs[p.PURL] = true
	}
	for _, f := range report.Findings {
		purl := ""
		for _, d := range f.Dimensions {
			if d.Key == "purl" {
				purl = d.Value
				break
			}
		}
		require.NotEmpty(t, purl, "finding %s missing purl dimension", f.Fingerprint)
		assert.True(t, vulnPURLs[domain.NormalizePURL(purl)], "finding purl %s not in inventory", purl)
	}

	// No inventory purl retains qualifiers.
	for _, p := range report.Packages {
		assert.NotContains(t, p.PURL, "?")
		assert.NotContains(t, p.PURL, "#")
	}
}

func packageByPURL(packages []domain.PackageRef, purl string) (domain.PackageRef, bool) {
	for _, p := range packages {
		if p.PURL == purl {
			return p, true
		}
	}
	return domain.PackageRef{}, false
}

func TestParse_MultiTypeScan(t *testing.T) {
	s := trivy.NewScanner()
	data, err := os.ReadFile("testdata/multi-type-scan.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	require.Len(t, report.Findings, 4)

	kinds := make(map[string]int)
	for _, f := range report.Findings {
		kinds[f.FindingKind]++
	}

	assert.Equal(t, 2, kinds["sca"])
	assert.Equal(t, 1, kinds["iac"])
	assert.Equal(t, 1, kinds["secret"])
}

func TestParse_InvalidJSON(t *testing.T) {
	s := trivy.NewScanner()
	_, err := s.Parse(context.Background(), []byte(`not json`))
	assert.Error(t, err)
}

func TestFindingKind(t *testing.T) {
	s := trivy.NewScanner()
	kinds := make([]string, 0, len(s.Descriptor().FindingKinds))
	for _, k := range s.Descriptor().FindingKinds {
		kinds = append(kinds, string(k))
	}
	// Trivy emits sca, secret, and iac findings from one report.
	assert.Contains(t, kinds, "sca")
	assert.Contains(t, kinds, "secret")
	assert.Contains(t, kinds, "iac")
}
