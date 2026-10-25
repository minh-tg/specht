package dependencycheck

import (
	"context"
	"testing"

	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/parser/parseutil"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mustConvert converts a decoded report with the default finding limit.
func mustConvert(t *testing.T, report dcReport) *domain.NormalizedReport {
	t.Helper()
	budget, err := parseutil.NewBudget(context.Background(), nil)
	require.NoError(t, err)
	nr, err := convert(budget, report)
	require.NoError(t, err)
	return nr
}

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

func TestExtractCVSS_VersionFromVectorPrefix(t *testing.T) {
	vuln := dcVulnerability{
		CvssV3: &dcCvss{BaseScore: 9.8, VectorString: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	}
	_, _, ver := extractCVSS(vuln)
	assert.Equal(t, "3.0", ver, "a 3.0 vector is not relabelled 3.1")
}

func TestDCCVSSAll(t *testing.T) {
	v3 := &dcCvss{BaseScore: 9.8, VectorString: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}
	v2 := &dcCvss{Score: 7.5, VectorString: "AV:N/AC:L/Au:N/C:P/I:P/A:P"}

	t.Run("keeps v3 and v2 with prefix-derived versions", func(t *testing.T) {
		got := dcCVSSAll(dcVulnerability{CvssV3: v3, CvssV2: v2, Source: "NVD"})
		assert.Equal(t, []domain.CVSSRecord{
			{Version: "3.0", Vector: v3.VectorString, Score: 9.8, Source: "nvd"},
			{Version: "2.0", Vector: "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", Score: 7.5, Source: "nvd"},
		}, got)
	})

	t.Run("source stays empty when the report names none", func(t *testing.T) {
		got := dcCVSSAll(dcVulnerability{CvssV2: v2})
		require.Len(t, got, 1)
		assert.Empty(t, got[0].Source)
	})

	t.Run("skips entries without a score or a usable vector", func(t *testing.T) {
		got := dcCVSSAll(dcVulnerability{
			CvssV3: &dcCvss{BaseScore: 0, VectorString: v3.VectorString},
			CvssV2: &dcCvss{Score: 5, VectorString: ""},
		})
		assert.Empty(t, got)
	})

	t.Run("nothing when no CVSS data", func(t *testing.T) {
		assert.Empty(t, dcCVSSAll(dcVulnerability{}))
	})
}

func TestCreateFingerprint(t *testing.T) {
	t.Run("with purl uses sca fingerprint format", func(t *testing.T) {
		fp := createFingerprint("CVE-2021-44228", "pkg:maven/log4j@2.0", "lib/log4j.jar", "log4j.jar")
		assert.Equal(t, "CVE-2021-44228:pkg:maven/log4j@2.0", fp)
	})

	t.Run("without purl falls back to the file path, then the file name", func(t *testing.T) {
		assert.Equal(t, "CVE-2021-44228:lib/app.dll", createFingerprint("CVE-2021-44228", "", "lib/app.dll", "app.dll"))
		assert.Equal(t, "CVE-2021-44228:app.dll", createFingerprint("CVE-2021-44228", "", "", "app.dll"))
		fp := createFingerprint("CVE-2021-44228", "", "", "")
		assert.Equal(t, "CVE-2021-44228:", fp)
	})
}

func TestConvertEdgeCases(t *testing.T) {
	t.Run("empty report", func(t *testing.T) {
		nr := mustConvert(t, dcReport{})
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
		nr := mustConvert(t, report)
		require := assert.New(t)
		require.Len(nr.Findings, 1)
		assert.Equal(t, "CVE-2024-0001:/path/to/orphan.jar", nr.Findings[0].Fingerprint)
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
		nr := mustConvert(t, report)
		assert.Empty(t, nr.Findings)
	})
}
