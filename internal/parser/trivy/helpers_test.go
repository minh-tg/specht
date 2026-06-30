package trivy

import (
	"testing"

	"github.com/vulnserve/vulnserve/internal/scanner"
)

func TestNormalizeSeverity(t *testing.T) {
	tests := []struct {
		input string
		want  scanner.Severity
	}{
		{"CRITICAL", scanner.SeverityCritical},
		{"critical", scanner.SeverityCritical},
		{"Critical", scanner.SeverityCritical},
		{"HIGH", scanner.SeverityHigh},
		{"MEDIUM", scanner.SeverityMedium},
		{"LOW", scanner.SeverityLow},
		{"", scanner.SeverityUnknown},
		{"UNKNOWN", scanner.SeverityUnknown},
		{"INFO", scanner.SeverityUnknown},
		{"NONE", scanner.SeverityUnknown},
		{"random_string", scanner.SeverityUnknown},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeSeverity(tt.input)
			if got != tt.want {
				t.Errorf("normalizeSeverity(%q) = %d, want %d", tt.input, got, tt.want)
			}
		})
	}
}

func TestDetectEdgeCases(t *testing.T) {
	p := &Parser{}

	t.Run("empty array returns false", func(t *testing.T) {
		if p.Detect([]byte(`[]`)) {
			t.Error("Detect([]) returned true, want false")
		}
	})

	t.Run("result with empty target returns false", func(t *testing.T) {
		data := []byte(`[{"Target":"","Class":"os-pkgs"}]`)
		if p.Detect(data) {
			t.Error("Detect([{empty target}]) returned true, want false")
		}
	})

	t.Run("invalid JSON returns false", func(t *testing.T) {
		if p.Detect([]byte(`{invalid`)) {
			t.Error("Detect(invalid) returned true, want false")
		}
	})
}

func TestConvertEdgeCases(t *testing.T) {
	t.Run("empty report returns empty findings", func(t *testing.T) {
		nr := convert(trivyReport{})
		if nr == nil {
			t.Fatal("convert returned nil")
		}
		if len(nr.Findings) != 0 {
			t.Errorf("expected 0 findings, got %d", len(nr.Findings))
		}
		if nr.ScanType != scanner.ScanTypeImage {
			t.Errorf("ScanType = %q, want %q", nr.ScanType, scanner.ScanTypeImage)
		}
	})

	t.Run("empty vulnerabilities list", func(t *testing.T) {
		result := trivyResult{
			Target: "test:latest",
			Class:  "os-pkgs",
		}
		nr := convert(trivyReport{result})
		if len(nr.Findings) != 0 {
			t.Errorf("expected 0 findings for empty vulns, got %d", len(nr.Findings))
		}
	})

	t.Run("unknown class maps to filesystem", func(t *testing.T) {
		result := trivyResult{
			Target: "some-target",
			Class:  "custom-class",
		}
		nr := convert(trivyReport{result})
		if nr.Target.Kind != "filesystem" {
			t.Errorf("Target.Kind = %q, want 'filesystem'", nr.Target.Kind)
		}
	})
}

func TestConvertScoreSelection(t *testing.T) {
	t.Run("prefers nvd v4 over v3", func(t *testing.T) {
		result := trivyResult{
			Target: "test:latest",
			Class:  "os-pkgs",
			Vulnerabilities: []trivyVuln{
				{
					VulnerabilityID: "CVE-2024-0001",
					PkgID:           "libfoo@1.0",
					PkgName:         "libfoo",
					InstalledVersion: "1.0",
					Severity:        "HIGH",
					CVSS: map[string]trivyCVSS{
						"nvd": {V4Score: 8.5, V3Score: 7.5},
					},
				},
			},
		}
		nr := convert(trivyReport{result})
		if len(nr.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(nr.Findings))
		}
		if nr.Findings[0].Score != 8.5 {
			t.Errorf("score = %f, want 8.5", nr.Findings[0].Score)
		}
	})

	t.Run("falls back to redhat if nvd missing", func(t *testing.T) {
		result := trivyResult{
			Target: "test:latest",
			Class:  "os-pkgs",
			Vulnerabilities: []trivyVuln{
				{
					VulnerabilityID: "CVE-2024-0002",
					PkgID:           "libbar@1.0",
					PkgName:         "libbar",
					InstalledVersion: "1.0",
					Severity:        "MEDIUM",
					CVSS: map[string]trivyCVSS{
						"redhat": {V4Score: 6.5},
					},
				},
			},
		}
		nr := convert(trivyReport{result})
		if nr.Findings[0].Score != 6.5 {
			t.Errorf("score = %f, want 6.5", nr.Findings[0].Score)
		}
	})

	t.Run("falls back to v2 when no v4 or v3 scores", func(t *testing.T) {
		result := trivyResult{
			Target: "test:latest",
			Class:  "os-pkgs",
			Vulnerabilities: []trivyVuln{
				{
					VulnerabilityID: "CVE-2024-0003",
					PkgID:           "libbaz@1.0",
					PkgName:         "libbaz",
					InstalledVersion: "1.0",
					Severity:        "LOW",
					CVSS: map[string]trivyCVSS{
						"nvd": {V2Score: 4.0},
					},
				},
			},
		}
		nr := convert(trivyReport{result})
		if nr.Findings[0].Score != 4.0 {
			t.Errorf("score = %f, want 4.0", nr.Findings[0].Score)
		}
	})

	t.Run("zero score when no CVSS data", func(t *testing.T) {
		result := trivyResult{
			Target: "test:latest",
			Class:  "os-pkgs",
			Vulnerabilities: []trivyVuln{
				{
					VulnerabilityID: "CVE-2024-0004",
					PkgID:           "libqux@1.0",
					PkgName:         "libqux",
					InstalledVersion: "1.0",
					Severity:        "HIGH",
				},
			},
		}
		nr := convert(trivyReport{result})
		if nr.Findings[0].Score != 0 {
			t.Errorf("score = %f, want 0 for no CVSS data", nr.Findings[0].Score)
		}
	})

	t.Run("PURL from PkgIdentifier when available", func(t *testing.T) {
		result := trivyResult{
			Target: "test:latest",
			Class:  "os-pkgs",
			Vulnerabilities: []trivyVuln{
				{
					VulnerabilityID: "CVE-2024-0005",
					PkgID:           "fallback-pkg@1.0",
					PkgName:         "test-pkg",
					InstalledVersion: "1.0",
					Severity:        "HIGH",
					PkgIdentifier: trivyPkgIdentifier{
						PURL: "pkg:apk/test-pkg@1.0",
					},
				},
			},
		}
		nr := convert(trivyReport{result})
		if len(nr.Findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(nr.Findings))
		}
		fp := string(scanner.SCAFingerprint("CVE-2024-0005", "pkg:apk/test-pkg@1.0"))
		if nr.Findings[0].Fingerprint != fp {
			t.Errorf("fingerprint = %q, want %q", nr.Findings[0].Fingerprint, fp)
		}
	})
}
