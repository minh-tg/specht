package dependencycheck

import (
	"testing"

	"github.com/minh-tg/specht/internal/domain"

	"github.com/stretchr/testify/assert"
)

func TestNormalizeDCSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  domain.Severity
	}{
		{"CRITICAL", domain.SeverityCritical},
		{"critical", domain.SeverityCritical},
		{"Critical", domain.SeverityCritical},
		{"HIGH", domain.SeverityHigh},
		{"MEDIUM", domain.SeverityMedium},
		{"LOW", domain.SeverityLow},
		{"", domain.SeverityUnknown},
		{"UNKNOWN", domain.SeverityUnknown},
		{"INFO", domain.SeverityUnknown},
		{"NONE", domain.SeverityUnknown},
		{"random_string", domain.SeverityUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeDCSeverity(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestExtractCVSS(t *testing.T) {
	t.Run("prefers v3 over v2", func(t *testing.T) {
		vuln := dcVulnerability{
			CvssV3: &dcCvss{BaseScore: 9.0, VectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
			CvssV2: &dcCvss{Score: 5.0, VectorString: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		}
		score, vec, ver := extractCVSS(vuln)
		assert.Equal(t, 9.0, score)
		assert.Equal(t, "3.1", ver)
		assert.Contains(t, vec, "CVSS:3.1")
	})

	t.Run("falls back to v2 when no v3", func(t *testing.T) {
		vuln := dcVulnerability{
			CvssV2: &dcCvss{Score: 5.0, VectorString: "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		}
		score, vec, ver := extractCVSS(vuln)
		assert.Equal(t, 5.0, score)
		assert.Equal(t, "2.0", ver)
		assert.Equal(t, "AV:N/AC:L/Au:N/C:P/I:P/A:P", vec)
	})

	t.Run("zero when no CVSS data", func(t *testing.T) {
		vuln := dcVulnerability{}
		score, _, _ := extractCVSS(vuln)
		assert.Equal(t, 0.0, score)
	})

	t.Run("zero when CVSS with zero score", func(t *testing.T) {
		vuln := dcVulnerability{
			CvssV3: &dcCvss{BaseScore: 0},
		}
		score, _, _ := extractCVSS(vuln)
		assert.Equal(t, 0.0, score)
	})
}

func TestCreateFingerprint(t *testing.T) {
	t.Run("with purl uses sca fingerprint format", func(t *testing.T) {
		fp := createFingerprint("CVE-2021-44228", "pkg:maven/log4j@2.0")
		assert.Equal(t, "CVE-2021-44228:pkg:maven/log4j@2.0", fp)
	})

	t.Run("without purl uses vuln id with trailing colon", func(t *testing.T) {
		fp := createFingerprint("CVE-2021-44228", "")
		assert.Equal(t, "CVE-2021-44228:", fp)
	})
}

func TestConvertEdgeCases(t *testing.T) {
	t.Run("empty report", func(t *testing.T) {
		nr := convert(dcReport{})
		require := assert.New(t)
		require.NotNil(nr)
		require.Empty(nr.Findings)
	})

	t.Run("dependency with no packages", func(t *testing.T) {
		report := dcReport{
			ReportSchema: "2.0",
			Dependencies: []dcDependency{
				{
					FileName: "orphan.jar",
					FilePath: "/path/to/orphan.jar",
					Vulnerabilities: []dcVulnerability{
						{Name: "CVE-2024-0001", Severity: "HIGH"},
					},
				},
			},
		}
		nr := convert(report)
		require := assert.New(t)
		require.Len(nr.Findings, 1)
		assert.Equal(t, "CVE-2024-0001:", nr.Findings[0].Fingerprint)
	})

	t.Run("dependency with no vulnerabilities", func(t *testing.T) {
		report := dcReport{
			ReportSchema: "2.0",
			Dependencies: []dcDependency{
				{
					FileName: "clean.jar",
					FilePath: "/path/to/clean.jar",
					Packages: []dcPackage{
						{ID: "pkg:maven/clean@1.0"},
					},
				},
			},
		}
		nr := convert(report)
		assert.Empty(t, nr.Findings)
	})
}
