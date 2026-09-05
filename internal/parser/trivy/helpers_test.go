package trivy

import (
	"testing"

	"github.com/xMinhx/specht/internal/domain"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeSeverity(t *testing.T) {
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
			got := normalizeSeverity(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestDetectEdgeCases(t *testing.T) {
	s := &Scanner{}

	t.Run("empty array returns false", func(t *testing.T) {
		assert.False(t, s.DetectFormat([]byte(`[]`)))
	})

	t.Run("result with empty target returns false", func(t *testing.T) {
		data := []byte(`[{"Target":"","Class":"os-pkgs"}]`)
		assert.False(t, s.DetectFormat(data))
	})

	t.Run("invalid JSON returns false", func(t *testing.T) {
		assert.False(t, s.DetectFormat([]byte(`{invalid`)))
	})
}

func TestConvertEdgeCases(t *testing.T) {
	t.Run("empty report returns empty findings", func(t *testing.T) {
		nr := convert(trivyReport{})
		require.NotNil(t, nr)
		assert.Empty(t, nr.Findings)
		assert.Equal(t, domain.ScanTypeImage, nr.ScanType)
	})

	t.Run("empty vulnerabilities list", func(t *testing.T) {
		result := trivyResult{
			Target: "test:latest",
			Class:  "os-pkgs",
		}
		nr := convert(trivyReport{result})
		assert.Empty(t, nr.Findings)
	})

	t.Run("unknown class maps to filesystem", func(t *testing.T) {
		result := trivyResult{
			Target: "some-target",
			Class:  "custom-class",
		}
		nr := convert(trivyReport{result})
		assert.Equal(t, "filesystem", nr.Target.Kind)
	})
}

func TestConvertScoreSelection(t *testing.T) {
	t.Run("prefers nvd v4 over v3", func(t *testing.T) {
		result := trivyResult{
			Target: "test:latest",
			Class:  "os-pkgs",
			Vulnerabilities: []trivyVuln{
				{
					VulnerabilityID:  "CVE-2024-0001",
					PkgID:            "libfoo@1.0",
					PkgName:          "libfoo",
					InstalledVersion: "1.0",
					Severity:         "HIGH",
					CVSS: map[string]trivyCVSS{
						"nvd": {V4Score: 8.5, V3Score: 7.5},
					},
				},
			},
		}
		nr := convert(trivyReport{result})
		require.Len(t, nr.Findings, 1)
		assert.Equal(t, 8.5, nr.Findings[0].Score)
	})

	t.Run("falls back to redhat if nvd missing", func(t *testing.T) {
		result := trivyResult{
			Target: "test:latest",
			Class:  "os-pkgs",
			Vulnerabilities: []trivyVuln{
				{
					VulnerabilityID:  "CVE-2024-0002",
					PkgID:            "libbar@1.0",
					PkgName:          "libbar",
					InstalledVersion: "1.0",
					Severity:         "MEDIUM",
					CVSS: map[string]trivyCVSS{
						"redhat": {V4Score: 6.5},
					},
				},
			},
		}
		nr := convert(trivyReport{result})
		assert.Equal(t, 6.5, nr.Findings[0].Score)
	})

	t.Run("falls back to v2 when no v4 or v3 scores", func(t *testing.T) {
		result := trivyResult{
			Target: "test:latest",
			Class:  "os-pkgs",
			Vulnerabilities: []trivyVuln{
				{
					VulnerabilityID:  "CVE-2024-0003",
					PkgID:            "libbaz@1.0",
					PkgName:          "libbaz",
					InstalledVersion: "1.0",
					Severity:         "LOW",
					CVSS: map[string]trivyCVSS{
						"nvd": {V2Score: 4.0},
					},
				},
			},
		}
		nr := convert(trivyReport{result})
		assert.Equal(t, 4.0, nr.Findings[0].Score)
	})

	t.Run("zero score when no CVSS data", func(t *testing.T) {
		result := trivyResult{
			Target: "test:latest",
			Class:  "os-pkgs",
			Vulnerabilities: []trivyVuln{
				{
					VulnerabilityID:  "CVE-2024-0004",
					PkgID:            "libqux@1.0",
					PkgName:          "libqux",
					InstalledVersion: "1.0",
					Severity:         "HIGH",
				},
			},
		}
		nr := convert(trivyReport{result})
		assert.Equal(t, 0.0, nr.Findings[0].Score)
	})

	t.Run("PURL from PkgIdentifier when available", func(t *testing.T) {
		result := trivyResult{
			Target: "test:latest",
			Class:  "os-pkgs",
			Vulnerabilities: []trivyVuln{
				{
					VulnerabilityID:  "CVE-2024-0005",
					PkgID:            "fallback-pkg@1.0",
					PkgName:          "test-pkg",
					InstalledVersion: "1.0",
					Severity:         "HIGH",
					PkgIdentifier: trivyPkgIdentifier{
						PURL: "pkg:apk/test-pkg@1.0",
					},
				},
			},
		}
		nr := convert(trivyReport{result})
		require.Len(t, nr.Findings, 1)
		fp := string(domain.SCAFingerprint("CVE-2024-0005", "pkg:apk/test-pkg@1.0"))
		assert.Equal(t, fp, nr.Findings[0].Fingerprint)
	})
}
