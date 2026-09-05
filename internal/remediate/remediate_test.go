package remediate

import (
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

func TestSuggest_AlwaysOneSuggestion(t *testing.T) {
	for _, kind := range []string{"sca", "sast", "iac", "secret", "dast", "unknown-kind", ""} {
		s := Suggest(Input{FindingID: "f1", FindingKind: kind})
		assert.NotEmpty(t, s.Action)
		assert.NotEmpty(t, s.Detail, kind)
		assert.NotEmpty(t, s.Confidence, kind)
	}
}
