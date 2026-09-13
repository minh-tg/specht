package usecase

import (
	"context"
	"fmt"
	"strings"

	"github.com/xMinhx/specht/internal/gate"
	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/provider"
)

// defaultProvider is the adapter used when callers name none.
const defaultProvider = "github"

// PRCheckPreviewInput scopes a pull-request check preview: the revision
// under review and, optionally, the exact report that scanned it.
type PRCheckPreviewInput struct {
	ProjectSlug string
	Provider    string
	CommitSha   string
	// ReportID ties the check to one exact scan. Empty scopes by commit:
	// findings the commit introduced, whatever report observed them.
	ReportID string
	// MinSeverityRank floors the findings a check considers (<=0 means high).
	MinSeverityRank int16
}

// PRCheckAnnotation is one planned inline annotation.
type PRCheckAnnotation struct {
	ExternalID string `json:"external_id"`
	FindingID  string `json:"finding_id"`
	File       string `json:"file"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	Level      string `json:"level"`
	Title      string `json:"title"`
	Message    string `json:"message"`
}

// PRCheckPreview is the publishable check plan for a change: one
// conclusion tied to the exact scan and commit, bounded annotations for
// findings with mappable locations, and summary counts covering the rest.
// Nothing here touches a live platform — previews render the exact payload
// a publish step would send.
type PRCheckPreview struct {
	Provider      string              `json:"provider"`
	CommitSha     string              `json:"commit_sha"`
	ReportID      string              `json:"report_id,omitempty"`
	Conclusion    string              `json:"conclusion"`
	Title         string              `json:"title"`
	Summary       string              `json:"summary"`
	Annotations   []PRCheckAnnotation `json:"annotations"`
	SummaryCounts map[string]int      `json:"summary_counts"`
	Truncated     bool                `json:"truncated"`
	Supersedes    string              `json:"supersedes,omitempty"`
	WaivedCount   int                 `json:"waived_count"`
}

// PreviewPRCheck plans (but never publishes) the pull-request check for a
// change. Findings without a mappable location degrade to summary counts;
// waived findings never annotate.
func (u *Usecases) PreviewPRCheck(ctx context.Context, input PRCheckPreviewInput) (*PRCheckPreview, error) {
	if strings.TrimSpace(input.CommitSha) == "" {
		return nil, fmt.Errorf("commit_sha is required")
	}
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", input.ProjectSlug, err)
	}

	name := input.Provider
	if name == "" {
		name = defaultProvider
	}
	p, err := u.providers().Get(name)
	if err != nil {
		return nil, fmt.Errorf("unknown provider %q", name)
	}

	floor := input.MinSeverityRank
	if floor <= 0 {
		floor = 3
	}

	// Resolve the introduced set and the breach verdict together: report
	// scope ties to one exact scan, commit scope to the change.
	var introduced []port.Finding
	var decision gate.Decision
	branch := ""
	u.initGate()
	policies := gatePoliciesForProject(project)
	if input.ReportID != "" {
		introduced, err = u.deps.Stores.Findings.ListIntroducedByReport(ctx, project.ID, input.ReportID)
		if err != nil {
			return nil, fmt.Errorf("list introduced findings: %w", err)
		}
		report, err := u.deps.Stores.Reports.GetByID(ctx, input.ReportID)
		if err == nil && report.Branch != nil {
			branch = *report.Branch
		}
		decision, err = u.gate.EvaluateIntroducedOnly(ctx, project.ID, floor, input.ReportID, policies)
		if err != nil {
			return nil, fmt.Errorf("gate eval: %w", err)
		}
	} else {
		all, err := u.deps.Stores.Findings.ListByProject(ctx, project.ID, nil, nil, nil, nil, nil, 1000, 0)
		if err != nil {
			return nil, fmt.Errorf("list findings: %w", err)
		}
		for _, f := range all {
			if f.IntroducedCommitSha != nil && *f.IntroducedCommitSha == input.CommitSha {
				introduced = append(introduced, f)
			}
		}
		decision, err = u.gate.EvaluateIntroducedAtCommit(ctx, project.ID, floor, input.CommitSha, policies)
		if err != nil {
			return nil, fmt.Errorf("gate eval: %w", err)
		}
	}

	blocked := blockedSet(decision.BlockedBy)
	var findings []provider.Finding
	for _, f := range introduced {
		if f.CurrentSeverityRank < floor {
			continue
		}
		if _, ok := blocked[f.ID]; !ok {
			continue
		}
		detail, err := u.GetFinding(ctx, f.ID)
		if err != nil {
			return nil, fmt.Errorf("expand finding %q: %w", f.ID, err)
		}
		pf := provider.Finding{
			ID:           f.ID,
			Title:        f.CurrentTitle,
			Severity:     f.CurrentSeverity,
			SeverityRank: f.CurrentSeverityRank,
			Fingerprint:  f.Fingerprint,
			Introduced:   true,
		}
		if detail.Location != nil {
			pf.File = detail.Location.File
			pf.StartLine = detail.Location.StartLine
			pf.EndLine = detail.Location.EndLine
		}
		if detail.Remediation != nil {
			pf.RemediationURL = detail.Remediation.URL
		}
		findings = append(findings, pf)
	}

	plan, err := p.PlanCheck(provider.CheckInput{
		CommitSha: input.CommitSha,
		ReportID:  input.ReportID,
		Branch:    branch,
		Breached:  decision.Status == gate.StatusFail,
		Findings:  findings,
	})
	if err != nil {
		return nil, fmt.Errorf("plan check: %w", err)
	}

	out := &PRCheckPreview{
		Provider:      plan.Provider,
		CommitSha:     plan.CommitSha,
		ReportID:      plan.ReportID,
		Conclusion:    string(plan.Conclusion),
		Title:         plan.Title,
		Summary:       plan.Summary,
		SummaryCounts: plan.SummaryCounts,
		Truncated:     plan.Truncated,
		Supersedes:    plan.Supersedes,
		WaivedCount:   decision.WaivedCount,
	}
	for _, a := range plan.Annotations {
		out.Annotations = append(out.Annotations, PRCheckAnnotation{
			ExternalID: a.ExternalID,
			FindingID:  a.FindingID,
			File:       a.File,
			StartLine:  a.StartLine,
			EndLine:    a.EndLine,
			Level:      string(a.Level),
			Title:      a.Title,
			Message:    a.Message,
		})
	}
	return out, nil
}

// providers returns the configured provider registry, defaulting to a
// registry with the GitHub adapter so previews work without explicit
// composition-root wiring.
func (u *Usecases) providers() *provider.Registry {
	if u.deps.Providers != nil {
		return u.deps.Providers
	}
	reg := provider.NewRegistry()
	_ = reg.Register(provider.NewGitHubProvider())
	return reg
}

// blockedSet indexes gate blockers for membership tests.
func blockedSet(ids []string) map[string]struct{} {
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}
