package usecase

import (
	"context"

	"github.com/google/uuid"
	"github.com/xMinhx/specht/internal/patch"
)

// PreviewPatch plans (but never applies) the safe patch for one finding.
// GetFinding supplies the access check, evidence dimensions, and source
// guidance; patch.Propose decides support. Unsupported findings yield an
// explicit refusal with a reason — never a partial patch.
func (u *Usecases) PreviewPatch(ctx context.Context, findingID string) (*patch.Outcome, error) {
	if _, err := uuid.Parse(findingID); err != nil {
		return nil, ErrInvalidFindingID
	}
	detail, err := u.GetFinding(ctx, findingID)
	if err != nil {
		return nil, err
	}
	dims, err := u.deps.Stores.Findings.ListDimensions(ctx, detail.ID)
	if err != nil {
		return nil, err
	}
	dimMap := make(map[string]string, len(dims))
	for _, d := range dims {
		if _, ok := dimMap[d.Key]; !ok {
			dimMap[d.Key] = d.Value
		}
	}
	var fixSummary, fixURL, tool string
	if detail.Remediation != nil {
		fixSummary, fixURL = detail.Remediation.Summary, detail.Remediation.URL
	}
	if detail.Suggestion != nil {
		tool = detail.Suggestion.Source
	}
	commit := ""
	if detail.IntroducedCommitSha != nil {
		commit = *detail.IntroducedCommitSha
	} else if detail.Context != nil {
		commit = detail.Context.CommitSha
	}
	report := ""
	if detail.IntroducedByReportID != nil {
		report = *detail.IntroducedByReportID
	}
	outcome := patch.Propose(patch.Input{
		FindingID: detail.ID, FindingKind: detail.FindingKind, Title: detail.CurrentTitle,
		Dims: dimMap, FixSummary: fixSummary, FixURL: fixURL, Tool: tool,
		ReportID: report, CommitSha: commit,
	})
	return &outcome, nil
}
