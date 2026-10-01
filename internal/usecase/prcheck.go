package usecase

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/minh-tg/specht/internal/gate"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/provider"
)

// ErrUnknownProvider is returned when a preview names a provider the
// registry does not know. Callers map it to a client error (400).
var ErrUnknownProvider = errors.New("unknown provider")

// defaultProvider is the adapter used when callers name none.
const defaultProvider = "github"

// previewListPageSize bounds one finding-list page; listIntroducedAtCommit
// walks pages so large projects never silently drop findings from a check.
const previewListPageSize = 1000

// normalizeRevision canonicalizes a commit SHA for storage and comparison:
// surrounding whitespace dropped, hex lowercased. SHAs are
// case-insensitive; branch names are not (and never pass through here).
func normalizeRevision(rev string) string {
	return strings.ToLower(strings.TrimSpace(rev))
}

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
	TotalMappable int                 `json:"total_mappable"`
	Supersedes    string              `json:"supersedes,omitempty"`
	WaivedCount   int                 `json:"waived_count"`
}

// PreviewPRCheck plans (but never publishes) the pull-request check for a
// change. Findings without a mappable location degrade to summary counts;
// waived findings never annotate.
// previewScope is the resolved introduced-set + gate-verdict pair for one
// PR check preview: report scope ties to one exact scan, commit scope to
// the change.
type previewScope struct {
	introduced []port.Finding
	decision   gate.Decision
	branch     string
}

func (u *Usecases) PreviewPRCheck(ctx context.Context, input PRCheckPreviewInput) (*PRCheckPreview, error) {
	if strings.TrimSpace(input.CommitSha) == "" {
		return nil, fmt.Errorf("commit_sha is required")
	}
	input.CommitSha = normalizeRevision(input.CommitSha)
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, input.ProjectSlug, err)
	}

	name := input.Provider
	if name == "" {
		name = defaultProvider
	}
	p, err := u.providers().Get(name)
	if err != nil {
		return nil, fmt.Errorf("%w %q", ErrUnknownProvider, name)
	}

	floor := input.MinSeverityRank
	if floor <= 0 {
		floor = 3
	}

	u.initGate()
	scope, err := u.resolvePreviewScope(ctx, project, input, floor)
	if err != nil {
		return nil, err
	}

	findings, err := u.blockedProviderFindings(ctx, scope, floor)
	if err != nil {
		return nil, err
	}

	plan, err := p.PlanCheck(provider.CheckInput{
		CommitSha: input.CommitSha,
		ReportID:  input.ReportID,
		Branch:    scope.branch,
		Breached:  scope.decision.Status == gate.StatusFail,
		Findings:  findings,
	})
	if err != nil {
		return nil, fmt.Errorf("plan check: %w", err)
	}

	return buildPRCheckPreview(&plan, scope.decision), nil
}

// resolvePreviewScope resolves the introduced set and the breach verdict
// together for the requested scope (report ID or commit).
func (u *Usecases) resolvePreviewScope(ctx context.Context, project port.Project, input PRCheckPreviewInput, floor int16) (previewScope, error) {
	var scope previewScope
	policies := gatePoliciesForProject(project)
	var err error
	if input.ReportID == "" {
		scope.introduced, err = u.listIntroducedAtCommit(ctx, project.ID, input.CommitSha)
		if err != nil {
			return scope, fmt.Errorf("list findings: %w", err)
		}
		scope.decision, err = u.gate.EvaluateIntroducedAtCommit(ctx, project.ID, floor, input.CommitSha, policies)
		if err != nil {
			return scope, fmt.Errorf("gate eval: %w", err)
		}
		return scope, nil
	}
	return u.resolveReportScope(ctx, project, input, floor, policies)
}

// resolveReportScope resolves the introduced set and verdict for one exact
// report, validating that the report belongs to the project and scanned
// the requested commit.
func (u *Usecases) resolveReportScope(
	ctx context.Context,
	project port.Project,
	input PRCheckPreviewInput,
	floor int16,
	policies []gate.GatePolicy,
) (previewScope, error) {
	var scope previewScope
	report, err := u.deps.Stores.Reports.GetByID(ctx, input.ReportID)
	if err != nil {
		return scope, fmt.Errorf("lookup report %q: %w", input.ReportID, err)
	}
	if report.ProjectID != project.ID {
		return scope, ErrProjectAccessDenied
	}
	if report.CommitSha != nil && normalizeRevision(*report.CommitSha) != "" &&
		normalizeRevision(*report.CommitSha) != input.CommitSha {
		return scope, fmt.Errorf("report %q scanned commit %q, not %q", input.ReportID, *report.CommitSha, input.CommitSha)
	}
	if report.Branch != nil {
		scope.branch = *report.Branch
	}
	scope.introduced, err = u.deps.Stores.Findings.ListIntroducedByReport(ctx, project.ID, input.ReportID)
	if err != nil {
		return scope, fmt.Errorf("list introduced findings: %w", err)
	}
	scope.decision, err = u.gate.EvaluateIntroducedOnly(ctx, project.ID, floor, input.ReportID, policies)
	if err != nil {
		return scope, fmt.Errorf("gate eval: %w", err)
	}
	return scope, nil
}

// blockedProviderFindings maps the gate-blocked introduced findings (at or
// above the floor) into provider findings with display context attached.
func (u *Usecases) blockedProviderFindings(ctx context.Context, scope previewScope, floor int16) ([]provider.Finding, error) {
	blocked := blockedSet(scope.decision.BlockedBy)
	var blockedIntroduced []port.Finding
	var blockedIDs []string
	for _, f := range scope.introduced {
		if f.CurrentSeverityRank < floor {
			continue
		}
		if _, ok := blocked[f.ID]; !ok {
			continue
		}
		blockedIntroduced = append(blockedIntroduced, f)
		blockedIDs = append(blockedIDs, f.ID)
	}
	if len(blockedIntroduced) == 0 {
		return nil, nil
	}

	dcList, err := u.deps.Stores.Findings.ListFindingDisplayContextsByIDs(ctx, blockedIDs)
	if err != nil {
		return nil, fmt.Errorf("list finding display contexts: %w", err)
	}
	dcMap := make(map[string]port.FindingDisplayContext, len(dcList))
	for _, dc := range dcList {
		dcMap[dc.FindingID] = dc
	}

	findings := make([]provider.Finding, 0, len(blockedIntroduced))
	for _, f := range blockedIntroduced {
		pf := provider.Finding{
			ID:           f.ID,
			Title:        f.CurrentTitle,
			Severity:     f.CurrentSeverity,
			SeverityRank: f.CurrentSeverityRank,
			Fingerprint:  f.Fingerprint,
			Introduced:   true,
		}
		applyDisplayContext(&pf, dcMap[f.ID], f.FindingKind)
		findings = append(findings, pf)
	}
	return findings, nil
}

// applyDisplayContext fills location and remediation from the finding's
// stored display context when present.
func applyDisplayContext(pf *provider.Finding, dc port.FindingDisplayContext, findingKind string) {
	if dc.FindingID == "" {
		return
	}
	if loc := locationFromDisplay(dc.LocationSummary, dc.Metadata); loc != nil {
		pf.File = loc.File
		pf.StartLine = loc.StartLine
		pf.EndLine = loc.EndLine
	}
	if rem := remediationFromMetadata(dc.Metadata, dc.ToolName, findingKind, nil); rem != nil {
		pf.RemediationURL = rem.URL
	}
}

// buildPRCheckPreview projects a provider plan plus the gate decision onto
// the CLI/API preview shape.
func buildPRCheckPreview(plan *provider.CheckPlan, decision gate.Decision) *PRCheckPreview {
	out := &PRCheckPreview{
		Provider:      plan.Provider,
		CommitSha:     plan.CommitSha,
		ReportID:      plan.ReportID,
		Conclusion:    string(plan.Conclusion),
		Title:         plan.Title,
		Summary:       plan.Summary,
		SummaryCounts: plan.SummaryCounts,
		Truncated:     plan.Truncated,
		TotalMappable: plan.TotalMappable,
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
	return out
}

// providers returns the configured provider registry, defaulting to a
// registry with the GitHub adapter so previews work without explicit
// composition-root wiring.
func (u *Usecases) providers() ProviderRegistry {
	if u.deps.Providers != nil {
		return u.deps.Providers
	}
	reg := provider.NewRegistry()
	_ = reg.Register(provider.NewGitHubProvider())
	return reg
}

// listIntroducedAtCommit returns every finding a revision introduced,
// walking list pages so large projects never silently drop findings from
// a check. Stored commits are normalized at ingest; the input commit is
// normalized by the caller.
func (u *Usecases) listIntroducedAtCommit(ctx context.Context, projectID, commit string) ([]port.Finding, error) {
	var out []port.Finding
	for offset := int32(0); ; {
		page, err := u.deps.Stores.Findings.ListByProject(ctx, projectID, port.ListFindingsParams{Limit: previewListPageSize, Offset: offset})
		if err != nil {
			return nil, err
		}
		for _, f := range page {
			if f.IntroducedCommitSha != nil && normalizeRevision(*f.IntroducedCommitSha) == commit {
				out = append(out, f)
			}
		}
		if len(page) < previewListPageSize {
			return out, nil
		}
		offset += int32(len(page))
	}
}

// blockedSet indexes gate blockers for membership tests.
func blockedSet(ids []string) map[string]struct{} {
	out := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		out[id] = struct{}{}
	}
	return out
}
