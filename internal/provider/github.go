package provider

import (
	"fmt"
	"strings"
)

// githubProviderName is the canonical name of the GitHub adapter: the
// first repository-provider adapter.
const githubProviderName = "github"

// githubMaxAnnotations bounds inline annotations per check run, matching
// the GitHub Checks API limit so plans are publishable verbatim.
const githubMaxAnnotations = 50

// GitHubProvider plans GitHub check runs with inline annotations.
type GitHubProvider struct{}

// NewGitHubProvider builds the GitHub adapter.
func NewGitHubProvider() *GitHubProvider { return &GitHubProvider{} }

// Descriptor implements Provider.
func (p *GitHubProvider) Descriptor() Descriptor {
	return Descriptor{Name: githubProviderName, MaxAnnotations: githubMaxAnnotations}
}

// PlanCheck implements Provider: one conclusion tied to the exact scan
// and commit, stable external ids for rerun updates, graceful degradation
// for findings without a mappable file location.
func (p *GitHubProvider) PlanCheck(input CheckInput) (CheckPlan, error) {
	if strings.TrimSpace(input.CommitSha) == "" {
		return CheckPlan{}, fmt.Errorf("commit_sha is required")
	}

	findings := append([]Finding(nil), input.Findings...)
	SortFindings(findings)

	plan := CheckPlan{
		Provider:      githubProviderName,
		CommitSha:     input.CommitSha,
		ReportID:      input.ReportID,
		SummaryCounts: map[string]int{},
		Supersedes:    supersedesID(input.Repository, input.Branch),
	}
	annotated := 0
	for _, f := range findings {
		plan.SummaryCounts[severityBucket(f.Severity)]++
		if f.File == "" {
			continue
		}
		plan.TotalMappable++
		if annotated >= githubMaxAnnotations {
			plan.Truncated = true
			continue
		}
		plan.Annotations = append(plan.Annotations, Annotation{
			ExternalID: externalID(input.ReportID, f.Fingerprint),
			FindingID:  f.ID,
			File:       f.File,
			StartLine:  normLine(f.StartLine),
			EndLine:    normEndLine(f.StartLine, f.EndLine),
			Level:      levelFor(f.SeverityRank),
			Title:      f.Title,
			Message:    annotationMessage(f),
		})
		annotated++
	}

	switch {
	case input.Breached && len(plan.Annotations) > 0:
		plan.Conclusion = ConclusionFailure
	case input.Breached:
		// Breached but nothing mappable: still fail, summary carries it.
		plan.Conclusion = ConclusionFailure
	case len(plan.Annotations) == 0 && len(findings) > 0:
		plan.Conclusion = ConclusionNeutral
	default:
		plan.Conclusion = ConclusionSuccess
	}
	plan.Title = checkTitle(plan.Conclusion, len(findings), annotated)
	plan.Summary = checkSummary(input, plan)
	return plan, nil
}

// severityBucket normalizes a severity string for summary counts.
func severityBucket(severity string) string {
	s := strings.ToLower(strings.TrimSpace(severity))
	switch s {
	case "critical", "high", "medium", "low":
		return s
	default:
		return "unknown"
	}
}

// levelFor maps severity rank to an annotation level.
func levelFor(rank int16) AnnotationLevel {
	switch {
	case rank >= 3:
		return AnnotationError
	case rank == 2:
		return AnnotationWarning
	default:
		return AnnotationInfo
	}
}

// normLine clamps a line number to the 1-based range providers require.
func normLine(line int) int {
	if line < 1 {
		return 1
	}
	return line
}

// normEndLine defaults a missing end line to the (normalized) start line
// and clamps it below the start.
func normEndLine(start, end int) int {
	start = normLine(start)
	if end < start {
		return start
	}
	return end
}

// annotationMessage renders the annotation body: what, whether the change
// introduced it, and where to read more. No credentials, no raw payloads.
func annotationMessage(f Finding) string {
	var b strings.Builder
	b.WriteString(f.Title)
	if f.Introduced {
		b.WriteString(" (introduced by this change)")
	}
	if f.RemediationURL != "" {
		b.WriteString("\nRemediation: " + f.RemediationURL)
	}
	return b.String()
}

// checkTitle summarizes the verdict in one line.
func checkTitle(conclusion Conclusion, total, annotated int) string {
	switch conclusion {
	case ConclusionFailure:
		return fmt.Sprintf("Specht: %d blocking finding(s)", total)
	case ConclusionNeutral:
		return fmt.Sprintf("Specht: %d finding(s), none mappable to files", total)
	default:
		_ = annotated
		return "Specht: no blocking findings"
	}
}

// checkSummary renders the human-readable check body with scope, counts,
// and truncation notice.
func checkSummary(input CheckInput, plan CheckPlan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Scan report %s at %s", shortID(input.ReportID), shortID(input.CommitSha))
	if input.Branch != "" {
		fmt.Fprintf(&b, " on %s", input.Branch)
	}
	b.WriteString(".")
	if len(plan.SummaryCounts) > 0 {
		b.WriteString(" Findings:")
		for _, sev := range []string{"critical", "high", "medium", "low", "unknown"} {
			if n := plan.SummaryCounts[sev]; n > 0 {
				fmt.Fprintf(&b, " %s=%d", sev, n)
			}
		}
		b.WriteString(".")
	}
	if plan.Truncated {
		fmt.Fprintf(&b, " Showing %d of %d mappable annotations (provider cap).", len(plan.Annotations), plan.TotalMappable)
	}
	return b.String()
}

// externalID is stable across reruns so repeated scans update existing
// feedback instead of creating noise. Without a report scope it degrades
// to the bare fingerprint.
func externalID(reportID, fingerprint string) string {
	if strings.TrimSpace(reportID) == "" {
		return fingerprint
	}
	return fmt.Sprintf("%s:%s", reportID, fingerprint)
}

// supersedesID names the check run a rerun updates. Empty repository or
// branch yields "" — the platform then creates rather than updates.
func supersedesID(repository, branch string) string {
	if repository == "" || branch == "" {
		return ""
	}
	return fmt.Sprintf("specht:%s:%s", repository, branch)
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
