package usecase

import (
	"context"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/notify"
)

// PreviewNotification plans (but never sends) the issue-tracker or
// messaging action for one finding. GetFinding supplies the access check
// and evidence; notify.Build decides the sync action. Refusals carry a
// reason — never a partial plan.
func (u *Usecases) PreviewNotification(ctx context.Context, findingID, channel, target string, alreadyLinked bool) (*notify.Outcome, error) {
	if _, err := uuid.Parse(findingID); err != nil {
		return nil, ErrInvalidFindingID
	}
	detail, err := u.GetFinding(ctx, findingID)
	if err != nil {
		return nil, err
	}
	// The scanner's link is sent even when the summary is only the kind-level
	// label (Fallback), which is not worth sending.
	var remediation string
	if rem := detail.Remediation; rem != nil {
		remediation = rem.URL
		if remediation == "" && !rem.Fallback {
			remediation = rem.Summary
		}
	}
	introduced := ""
	if detail.IntroducedCommitSha != nil {
		introduced = *detail.IntroducedCommitSha
	}
	outcome := notify.Build(notify.Input{
		FindingID:     detail.ID,
		ProjectSlug:   detail.ProjectID,
		Title:         detail.CurrentTitle,
		Severity:      detail.CurrentSeverity,
		FindingKind:   detail.FindingKind,
		Fingerprint:   detail.Fingerprint,
		State:         detail.State,
		Channel:       notify.Channel(channel),
		Target:        target,
		AlreadyLinked: alreadyLinked,
		Remediation:   remediation,
		Introduced:    introduced,
	})
	return &outcome, nil
}
