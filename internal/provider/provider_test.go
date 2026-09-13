package provider

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistryRegisterGet(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(NewGitHubProvider()))
	p, err := r.Get("github")
	require.NoError(t, err)
	assert.Equal(t, "github", p.Descriptor().Name)
	assert.Equal(t, []string{"github"}, r.List())
}

func TestRegistryDuplicateAndInvalid(t *testing.T) {
	r := NewRegistry()
	require.NoError(t, r.Register(NewGitHubProvider()))
	assert.ErrorIs(t, r.Register(NewGitHubProvider()), ErrDuplicateName)
	assert.ErrorIs(t, r.Register(nil), ErrInvalidDescriptor)
	_, err := r.Get("gitlab")
	assert.ErrorIs(t, err, ErrNoMatch)
}

func TestPlanCheck_TiedToScanAndCommit(t *testing.T) {
	p := NewGitHubProvider()
	plan, err := p.PlanCheck(CheckInput{
		CommitSha: "abc123", ReportID: "r1", Branch: "main", Repository: "github://acme/app",
		Breached: true,
		Findings: []Finding{
			{ID: "f1", Title: "XSS", Severity: "high", SeverityRank: 3, Fingerprint: "fp1", File: "app/main.go", StartLine: 10, EndLine: 12, Introduced: true},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, ConclusionFailure, plan.Conclusion)
	assert.Equal(t, "abc123", plan.CommitSha)
	assert.Equal(t, "r1", plan.ReportID)
	require.Len(t, plan.Annotations, 1)
	a := plan.Annotations[0]
	assert.Equal(t, "r1:fp1", a.ExternalID, "stable external id lets reruns update")
	assert.Equal(t, "app/main.go", a.File)
	assert.Equal(t, AnnotationError, a.Level)
	assert.Contains(t, a.Message, "introduced by this change")
	assert.Equal(t, "specht:github://acme/app:main", plan.Supersedes)
}

func TestPlanCheck_DegradesWithoutLocation(t *testing.T) {
	p := NewGitHubProvider()
	plan, err := p.PlanCheck(CheckInput{
		CommitSha: "abc123", ReportID: "r1", Breached: true,
		Findings: []Finding{
			{ID: "f1", Title: "CVE-2024-1", Severity: "high", SeverityRank: 3, Fingerprint: "fp1"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, ConclusionFailure, plan.Conclusion, "breach still fails without mappable locations")
	assert.Empty(t, plan.Annotations)
	assert.Equal(t, 1, plan.SummaryCounts["high"])
	assert.Contains(t, plan.Summary, "high=1")

	// Informational findings without locations go neutral, not silent.
	plan, err = p.PlanCheck(CheckInput{
		CommitSha: "abc123", ReportID: "r1", Breached: false,
		Findings: []Finding{
			{ID: "f1", Title: "CVE-2024-1", Severity: "low", SeverityRank: 1, Fingerprint: "fp1"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, ConclusionNeutral, plan.Conclusion)
}

func TestPlanCheck_CapsAnnotations(t *testing.T) {
	p := NewGitHubProvider()
	var findings []Finding
	for i := 0; i < 60; i++ {
		findings = append(findings, Finding{
			ID: "f", Title: "t", Severity: "medium", SeverityRank: 2,
			Fingerprint: "fp", File: "a.go", StartLine: 1,
		})
	}
	plan, err := p.PlanCheck(CheckInput{CommitSha: "abc123", ReportID: "r1", Breached: true, Findings: findings})
	require.NoError(t, err)
	assert.Len(t, plan.Annotations, githubMaxAnnotations)
	assert.True(t, plan.Truncated)
	assert.Equal(t, 60, plan.SummaryCounts["medium"], "summary still covers everything")
}

func TestPlanCheck_RequiresScope(t *testing.T) {
	p := NewGitHubProvider()
	_, err := p.PlanCheck(CheckInput{})
	assert.ErrorContains(t, err, "commit_sha")

	// Report scope is optional: external ids degrade to fingerprints.
	plan, err := p.PlanCheck(CheckInput{
		CommitSha: "abc123",
		Findings: []Finding{
			{ID: "f1", Title: "XSS", Severity: "high", SeverityRank: 3, Fingerprint: "fp1", File: "a.go", StartLine: 2},
		},
	})
	require.NoError(t, err)
	require.Len(t, plan.Annotations, 1)
	assert.Equal(t, "fp1", plan.Annotations[0].ExternalID)
}

func TestPlanCheck_SuccessWhenClean(t *testing.T) {
	p := NewGitHubProvider()
	plan, err := p.PlanCheck(CheckInput{CommitSha: "abc123", ReportID: "r1"})
	require.NoError(t, err)
	assert.Equal(t, ConclusionSuccess, plan.Conclusion)
	assert.True(t, strings.Contains(plan.Title, "no blocking"))
}
