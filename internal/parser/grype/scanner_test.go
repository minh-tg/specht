package grype_test

import (
	"context"
	"os"
	"testing"

	"github.com/minh-tg/specht/internal/domain"

	"github.com/minh-tg/specht/internal/parser/grype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestName(t *testing.T) {
	s := grype.NewScanner()
	assert.Equal(t, "grype", s.Descriptor().Name)
}

func TestDetect_ValidInput(t *testing.T) {
	s := grype.NewScanner()
	data, err := os.ReadFile("testdata/grype-report.json")
	require.NoError(t, err)
	assert.True(t, s.DetectFormat(data))
}

func TestDetect_InvalidInput(t *testing.T) {
	s := grype.NewScanner()
	assert.False(t, s.DetectFormat([]byte(`{}`)))
	assert.False(t, s.DetectFormat([]byte(`not json`)))
}

func TestParse_GrypeReport(t *testing.T) {
	s := grype.NewScanner()
	data, err := os.ReadFile("testdata/grype-report.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	require.NotNil(t, report.Target)
	assert.Len(t, report.Findings, 2)

	tests := []struct {
		name        string
		fingerprint string
		severity    domain.Severity
		score       float64
		findingKind string
		cvssVersion string
		aliasesLen  int
		fixSummary  string
	}{
		{
			name:        "first finding should be CVE-2023-25165",
			fingerprint: "CVE-2023-25165:pkg:golang/helm.sh/helm/v3@v3.11.1",
			severity:    domain.SeverityHigh,
			score:       9.8,
			findingKind: "sca",
			cvssVersion: "3.1",
			aliasesLen:  1,
			fixSummary:  "v3.11.3, v3.10.3",
		},
		{
			name:        "second finding should be GHSA-c3h9-896r-86jm",
			fingerprint: "GHSA-c3h9-896r-86jm:pkg:golang/github.com/gogo/protobuf@v1.3.1",
			severity:    domain.SeverityCritical,
			score:       9.8,
			findingKind: "sca",
			cvssVersion: "3.1",
			aliasesLen:  1,
			fixSummary:  "v1.3.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := grypeFindingByFingerprint(t, report.Findings, tt.fingerprint)
			assert.Equal(t, tt.severity, f.Severity)
			assert.Equal(t, tt.findingKind, f.FindingKind)
			assert.Equal(t, tt.score, f.Score)
			assert.Len(t, f.Aliases, tt.aliasesLen)
			if tt.cvssVersion != "" {
				require.NotNil(t, f.CVSS)
				assert.Equal(t, tt.cvssVersion, f.CVSS.Version)
			}
			if tt.fixSummary != "" {
				require.NotNil(t, f.Fix)
				assert.Equal(t, tt.fixSummary, f.Fix.Summary)
			}
		})
	}
}

// grypeFindingByFingerprint returns the matching finding or fails the test.
func grypeFindingByFingerprint(t *testing.T, findings []domain.NormalizedFinding, fingerprint string) domain.NormalizedFinding {
	t.Helper()
	for _, f := range findings {
		if f.Fingerprint == fingerprint {
			return f
		}
	}
	t.Fatalf("finding with fingerprint %q not found", fingerprint)
	return domain.NormalizedFinding{}
}

func TestParse_GrypeFullReport(t *testing.T) {
	s := grype.NewScanner()
	data, err := os.ReadFile("testdata/grype-full.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)

	// Grype's standard JSON only reports matched (vulnerable) artifacts, so
	// findings and inventory are the same population here. Every matched
	// artifact is captured, deduplicated by normalized purl.
	require.Len(t, report.Findings, 105)
	require.GreaterOrEqual(t, len(report.Packages), 100)
	require.Equal(t, len(report.Packages), len(report.Findings))

	seen := map[string]bool{}
	lodashSeen := false
	for _, p := range report.Packages {
		assert.NotContains(t, p.PURL, "?")
		assert.NotContains(t, p.PURL, "#")
		assert.False(t, seen[p.PURL], "duplicate inventory purl %s", p.PURL)
		seen[p.PURL] = true
		assert.Equal(t, "npm", p.Ecosystem)
		assert.Equal(t, "/app/package-lock.json", p.ManifestPath)
		if p.Name == "lodash" {
			lodashSeen = true
			assert.Contains(t, p.PURL, "pkg:npm/lodash@")
			assert.NotEmpty(t, p.Version)
		}
	}
	assert.True(t, lodashSeen, "lodash missing from inventory")
}

func TestParse_InvalidJSON(t *testing.T) {
	s := grype.NewScanner()
	_, err := s.Parse(context.Background(), []byte(`not json`))
	assert.Error(t, err)
}

func TestFindingKind(t *testing.T) {
	s := grype.NewScanner()
	assert.Equal(t, "sca", string(s.Descriptor().FindingKinds[0]))
}

func TestParse_GrypeReport_Aliases(t *testing.T) {
	s := grype.NewScanner()
	data, err := os.ReadFile("testdata/grype-report.json")
	require.NoError(t, err)

	report, err := s.Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, report.Findings, 2)

	ghsaFinding := report.Findings[1]
	assert.Equal(t, "ghsa", ghsaFinding.Extensions["namespace"])
	assert.Equal(t, "CVE-2021-3121", ghsaFinding.Aliases[0])
}

func TestParse_GrypeReport_SCALocation(t *testing.T) {
	data, err := os.ReadFile("testdata/grype-report.json")
	require.NoError(t, err)

	report, err := grype.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)

	f := grypeFindingByFingerprint(t, report.Findings, "CVE-2023-25165:pkg:golang/helm.sh/helm/v3@v3.11.1")
	assert.Equal(t, "helm.sh/helm/v3 v3.11.1 in /app/go.mod", f.Location)
}

func TestParse_CVSSAllKeepsEverySourceAndVersion(t *testing.T) {
	data, err := os.ReadFile("testdata/grype-multi-cvss.json")
	require.NoError(t, err)
	report, err := grype.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.Len(t, report.Findings, 3)

	multi := report.Findings[0]
	assert.Equal(t, []domain.CVSSRecord{
		{Version: "3.0", Vector: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", Score: 9.8, Source: "nvd@nist.gov:primary"},
		{Version: "2.0", Vector: "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", Score: 7.5, Source: "nvd@nist.gov:primary"},
		{Version: "3.1", Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", Score: 8.6, Source: "security-advisories@github.com:secondary"},
		{Version: "4.0", Vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", Score: 8.7, Source: "security-advisories@github.com:secondary"},
	}, multi.CVSSAll)
	// The single preferred vector and the occurrence score are unchanged.
	require.NotNil(t, multi.CVSS)
	assert.Equal(t, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", multi.CVSS.Vector)
	assert.InDelta(t, 9.8, multi.Score, 0)

	related := report.Findings[1]
	require.Len(t, related.CVSSAll, 1, "a primary entry with no CVSS falls back to the related vulnerability")
	assert.Equal(t, "3.1", related.CVSSAll[0].Version)
	assert.Equal(t, "nvd@nist.gov:primary", related.CVSSAll[0].Source)

	assert.Empty(t, report.Findings[2].CVSSAll)
}

func TestParse_CVSSAllSourceIsEmptyWhenTheReportNamesNone(t *testing.T) {
	data, err := os.ReadFile("testdata/grype-report.json")
	require.NoError(t, err)
	report, err := grype.NewScanner().Parse(context.Background(), data)
	require.NoError(t, err)
	require.NotEmpty(t, report.Findings)
	first := report.Findings[0]
	require.Len(t, first.CVSSAll, 1)
	assert.Equal(t, "3.1", first.CVSSAll[0].Version)
	assert.Empty(t, first.CVSSAll[0].Source)
}
