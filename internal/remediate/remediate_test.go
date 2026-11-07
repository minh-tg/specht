package remediate

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSuggest_SCAUpgradeHigh(t *testing.T) {
	s := Suggest(Input{
		FindingID: "f1", FindingKind: "sca", Tool: "trivy",
		Dims: map[string]string{
			"package_name": "lodash", "installed_version": "4.17.20", "fixed_version": "4.17.21",
		},
	})
	assert.Equal(t, "upgrade", s.Action)
	assert.Equal(t, "lodash", s.Target)
	assert.Contains(t, s.Detail, "4.17.20")
	assert.Contains(t, s.Detail, "4.17.21")
	assert.Equal(t, ConfidenceHigh, s.Confidence)
	assert.Equal(t, "trivy", s.Source)
}

func TestSuggest_SCANoFixedVersionLow(t *testing.T) {
	s := Suggest(Input{
		FindingID: "f1", FindingKind: "sca", Tool: "grype",
		Dims: map[string]string{"package_name": "lodash"},
	})
	assert.Equal(t, "review", s.Action)
	assert.Equal(t, ConfidenceLow, s.Confidence)
	assert.Contains(t, s.Detail, "advisory")
}

func TestSuggest_IaCGuidelineMedium(t *testing.T) {
	s := Suggest(Input{
		FindingID: "f1", FindingKind: "iac", Tool: "checkov",
		Dims:   map[string]string{"rule_id": "CKV_AWS_19", "resource": "AWS::S3::Bucket.Data"},
		FixURL: "https://docs.bridgecrew.io/docs/x",
	})
	assert.Equal(t, "configure", s.Action)
	assert.Equal(t, "AWS::S3::Bucket.Data", s.Target)
	assert.Equal(t, ConfidenceMedium, s.Confidence)
}

func TestSuggest_SecretRotateHigh(t *testing.T) {
	s := Suggest(Input{
		FindingID: "f1", FindingKind: "secret", Tool: "gitleaks",
		Dims: map[string]string{"file": "creds.env", "rule_id": "aws-key"},
	})
	assert.Equal(t, "rotate", s.Action)
	assert.Equal(t, ConfidenceHigh, s.Confidence)
	assert.Contains(t, s.Detail, "rescan")
}

func TestSuggest_SASTFixMediumThenFallback(t *testing.T) {
	withFix := Suggest(Input{
		FindingID: "f1", FindingKind: "sast", Tool: "sarif",
		Dims: map[string]string{"file": "db.go"}, FixSummary: "Use parameterized queries.",
	})
	assert.Equal(t, "fix-code", withFix.Action)
	assert.Equal(t, ConfidenceMedium, withFix.Confidence)

	bare := Suggest(Input{FindingID: "f1", FindingKind: "sast", Tool: "semgrep"})
	assert.Equal(t, "review", bare.Action)
	assert.Equal(t, ConfidenceLow, bare.Confidence)
}

func TestSuggest_StructuredFixFields(t *testing.T) {
	tests := []struct {
		name string
		in   Input
		want Suggestion
	}{
		{
			name: "sca with fixed version",
			in: Input{
				FindingID: "f1", FindingKind: "sca", Tool: "trivy",
				Dims: map[string]string{
					"package_name": "lodash", "ecosystem": "npm",
					"installed_version": "4.17.20", "fixed_version": "4.17.21",
				},
			},
			want: Suggestion{
				Action: "upgrade", Fallback: false, Package: "lodash", Ecosystem: "npm",
				InstalledVersion: "4.17.20", FixedVersion: "4.17.21",
			},
		},
		{
			name: "sca without fixed version",
			in: Input{
				FindingID: "f1", FindingKind: "sca", Tool: "grype",
				Dims: map[string]string{
					"package_name": "lodash", "ecosystem": "npm", "installed_version": "4.17.20",
				},
			},
			want: Suggestion{
				Action: "review", Fallback: true, Package: "lodash", Ecosystem: "npm",
				InstalledVersion: "4.17.20",
			},
		},
		{
			name: "sca guidance without fixed version is not a fallback",
			in: Input{
				FindingID: "f1", FindingKind: "sca", Tool: "osv",
				Dims:       map[string]string{"package_name": "lodash", "ecosystem": "npm"},
				FixSummary: "Move to the 5.x line.",
			},
			want: Suggestion{Action: "upgrade", Fallback: false, Package: "lodash", Ecosystem: "npm"},
		},
		{
			name: "sast fallback carries no package fields",
			in: Input{
				FindingID: "f1", FindingKind: "sast", Tool: "semgrep",
				Dims: map[string]string{"file": "db.go", "package_name": "ignored"},
			},
			want: Suggestion{Action: "review", Fallback: true},
		},
		{
			name: "sast with fix summary",
			in: Input{
				FindingID: "f1", FindingKind: "sast", Tool: "sarif",
				Dims: map[string]string{"file": "db.go"}, FixSummary: "Use parameterized queries.",
			},
			want: Suggestion{Action: "fix-code", Fallback: false},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Suggest(tt.in)
			assert.Equal(t, tt.want.Action, got.Action)
			assert.Equal(t, tt.want.Fallback, got.Fallback)
			assert.Equal(t, tt.want.Package, got.Package)
			assert.Equal(t, tt.want.Ecosystem, got.Ecosystem)
			assert.Equal(t, tt.want.InstalledVersion, got.InstalledVersion)
			assert.Equal(t, tt.want.FixedVersion, got.FixedVersion)
		})
	}
}

func TestSuggest_AlwaysOneSuggestion(t *testing.T) {
	for _, kind := range []string{"sca", "sast", "iac", "secret", "dast", "unknown-kind", ""} {
		s := Suggest(Input{FindingID: "f1", FindingKind: kind})
		assert.NotEmpty(t, s.Action)
		assert.NotEmpty(t, s.Detail, kind)
		assert.NotEmpty(t, s.Confidence, kind)
	}
}

// No parser records an ecosystem dimension, so a scanner's dependency finding has
// only its package URL to say which ecosystem it is in.
func TestSuggestReadsTheEcosystemFromThePackageURL(t *testing.T) {
	got := Suggest(Input{
		FindingKind: "sca",
		Dims: map[string]string{
			"package_name": "lodash", "purl": "pkg:npm/lodash@4.17.20",
			"installed_version": "4.17.20", "fixed_version": "4.18.0",
		},
	})
	if got.Ecosystem != "npm" {
		t.Fatalf("Ecosystem = %q, want npm", got.Ecosystem)
	}
}

func TestSuggestPrefersAnEcosystemTheFindingNames(t *testing.T) {
	got := Suggest(Input{
		FindingKind: "sca",
		Dims:        map[string]string{"ecosystem": "PyPI", "purl": "pkg:pypi/django@4.0"},
	})
	if got.Ecosystem != "PyPI" {
		t.Fatalf("Ecosystem = %q, want PyPI", got.Ecosystem)
	}
}

// A watcher finding has no scanner evidence, only what the advisory said about a
// package in the inventory, so it was left with the generic "review" fallback.
func TestSuggestTreatsAWatcherFindingAsADependencyUpgrade(t *testing.T) {
	got := Suggest(Input{
		FindingKind: "cve_watcher",
		Tool:        "CVE watcher",
		Dims: map[string]string{
			"purl": "pkg:npm/lodash@4.17.20", "ecosystem": "npm",
			"installed_version": "4.17.20", "fixed_version": "4.19.0",
		},
	})
	if got.Fallback || got.Action != "upgrade" || got.Confidence != ConfidenceHigh {
		t.Fatalf("suggestion = %+v, want a high confidence upgrade", got)
	}
	if got.Package != "lodash" || got.FixedVersion != "4.19.0" || got.Ecosystem != "npm" {
		t.Fatalf("suggestion = %+v, want lodash, 4.19.0, npm", got)
	}
	if !strings.Contains(got.Detail, "Upgrade lodash from 4.17.20 to 4.19.0") {
		t.Fatalf("detail = %q", got.Detail)
	}
}
