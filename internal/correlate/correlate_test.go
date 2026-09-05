package correlate

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMinhx/specht/internal/domain"
)

func sca(vuln, pkg, eco string, aliases ...string) domain.NormalizedFinding {
	dims := []domain.Dimension{
		{Key: domain.DimVulnerabilityID, Value: vuln},
		{Key: domain.DimPackageName, Value: pkg},
	}
	if eco != "" {
		dims = append(dims, domain.Dimension{Key: domain.DimEcosystem, Value: eco})
	}
	return domain.NormalizedFinding{
		Fingerprint: "fp-" + vuln + "-" + pkg,
		FindingKind: "sca", Title: vuln + " in " + pkg,
		Aliases: aliases, Dimensions: dims,
	}
}

func TestCorrelate_CrossToolSCA(t *testing.T) {
	// Trivy leads with the CVE, Grype with the GHSA; aliases converge them.
	trivy := sca("CVE-2024-1111", "lodash", "npm", "GHSA-1")
	grype := sca("GHSA-1", "lodash", "npm", "CVE-2024-1111")
	res := Correlate([]domain.NormalizedFinding{trivy, grype})
	require.Len(t, res.Groups, 1)
	g := res.Groups[0]
	assert.Equal(t, ConfidenceHigh, g.Confidence)
	assert.Equal(t, []int{0, 1}, g.Members)
	assert.Contains(t, g.Key, "CVE-2024-1111")
	assert.Empty(t, res.Uncertain)
}

func TestCorrelate_SharedVulnNeverGroupsAcrossPackages(t *testing.T) {
	a := sca("CVE-2024-1111", "lodash", "npm")
	b := sca("CVE-2024-1111", "axios", "npm")
	res := Correlate([]domain.NormalizedFinding{a, b})
	assert.Empty(t, res.Groups, "same CVE on different packages must not merge")
	require.Len(t, res.Uncertain, 1, "shared signal is review-only")
	assert.Equal(t, []int{0, 1}, res.Uncertain[0].Members)
}

func TestCorrelate_SASTIgnoresLines(t *testing.T) {
	mk := func(line int) domain.NormalizedFinding {
		return domain.NormalizedFinding{
			Fingerprint: "sast",
			FindingKind: "sast",
			Dimensions: []domain.Dimension{
				{Key: domain.DimRuleID, Value: "go-sql-injection"},
				{Key: domain.DimFile, Value: "db.go"},
				{Key: domain.DimLine, Value: string(rune('0' + line))},
			},
		}
	}
	res := Correlate([]domain.NormalizedFinding{mk(10), mk(42)})
	require.Len(t, res.Groups, 1)
	assert.Contains(t, res.Groups[0].Reason, "line shifts ignored")
}

func TestCorrelate_SASTDifferentFilesUncertain(t *testing.T) {
	mk := func(file string) domain.NormalizedFinding {
		return domain.NormalizedFinding{
			FindingKind: "sast",
			Dimensions: []domain.Dimension{
				{Key: domain.DimRuleID, Value: "go-sql-injection"},
				{Key: domain.DimFile, Value: file},
			},
		}
	}
	res := Correlate([]domain.NormalizedFinding{mk("a.go"), mk("b.go")})
	assert.Empty(t, res.Groups)
	require.Len(t, res.Uncertain, 1)
}

func TestCorrelate_SecretAndIaC(t *testing.T) {
	secret := func(target string) domain.NormalizedFinding {
		return domain.NormalizedFinding{
			FindingKind: "secret", Location: target,
			Dimensions: []domain.Dimension{{Key: domain.DimRuleID, Value: "aws-key"}},
		}
	}
	iac := func(resource string) domain.NormalizedFinding {
		return domain.NormalizedFinding{
			FindingKind: "iac", Resource: resource,
			Dimensions: []domain.Dimension{{Key: domain.DimRuleID, Value: "CKV_AWS_1"}},
		}
	}
	res := Correlate([]domain.NormalizedFinding{secret("repo/.env"), secret("repo/.env"), iac("aws_s3_bucket.data"), iac("aws_s3_bucket.data")})
	require.Len(t, res.Groups, 2)
	assert.Empty(t, res.Uncertain)
}

func TestCorrelate_UnknownKindsNeverGroup(t *testing.T) {
	a := domain.NormalizedFinding{FindingKind: "dast", Fingerprint: "a"}
	b := domain.NormalizedFinding{FindingKind: "dast", Fingerprint: "b"}
	res := Correlate([]domain.NormalizedFinding{a, b})
	assert.Empty(t, res.Groups)
	assert.Empty(t, res.Uncertain)
}

func TestCorrelate_DeterministicUnderShuffle(t *testing.T) {
	a := sca("CVE-2024-1111", "lodash", "npm", "GHSA-1")
	b := sca("GHSA-1", "lodash", "npm", "CVE-2024-1111")
	c := sca("CVE-2024-2222", "axios", "npm")
	first := Correlate([]domain.NormalizedFinding{a, b, c})
	second := Correlate([]domain.NormalizedFinding{c, b, a})
	require.Len(t, first.Groups, 1)
	require.Len(t, second.Groups, 1)
	assert.Equal(t, first.Groups[0].ID, second.Groups[0].ID)
	assert.Equal(t, first.Groups[0].Key, second.Groups[0].Key)
}
