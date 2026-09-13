package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/tracker"
)

// Verify outcomes for evidence-backed rescan verification.
const (
	// VerifyFixed means a newer complete scan from the same scanner no
	// longer observes the finding: the technical state moved to fixed and
	// the verifying scan is recorded on the event.
	VerifyFixed = "verified_fixed"
	// VerifyPresent means the newest complete scan still observes it.
	VerifyPresent = "still_present"
	// VerifyInconclusive means no scan can settle it (no newer completed
	// report, stale basis, or partial scope).
	VerifyInconclusive = "inconclusive"
)

// VerifyResponse is the outcome of one verification check.
type VerifyResponse struct {
	FindingID string  `json:"finding_id"`
	Outcome   string  `json:"outcome"`
	ReportID  *string `json:"report_id,omitempty"`
	Detail    string  `json:"detail"`
}

// VerifyFix checks a finding against the newest completed full rescan from
// the scanner that last observed it. Only a complete, newer, same-scanner
// full report that lacks the finding verifies the fix — incremental scans
// never qualify as a basis (their absence proves nothing); anything else
// is an explicit still_present or inconclusive verdict with the reason.
//
// Verification moves the scan-derived technical state to fixed and logs a
// verified_fixed event carrying the verifying report, branch, and commit.
// It never touches analyst state: triage standing is preserved. Triage
// cannot produce fixed — this is its only path, so a status edit alone
// can never claim a verified fix.
func (u *Usecases) VerifyFix(ctx context.Context, findingID string) (*VerifyResponse, error) {
	fid, err := uuid.Parse(findingID)
	if err != nil {
		return nil, fmt.Errorf("invalid finding id: %w", err)
	}
	f, err := u.findingWithProjectAccess(ctx, fid)
	if err != nil {
		return nil, err
	}

	dc, err := u.deps.Stores.Findings.GetFindingDisplayContext(ctx, fid.String())
	if err != nil || dc.ToolName == "" {
		return &VerifyResponse{
			FindingID: fid.String(), Outcome: VerifyInconclusive,
			Detail: "no linked scan occurrence to verify against",
		}, nil
	}

	report, err := u.deps.Stores.Reports.LatestCompletedByScanner(ctx, f.ProjectID, dc.ToolName)
	if err != nil {
		return &VerifyResponse{
			FindingID: fid.String(), Outcome: VerifyInconclusive,
			Detail: fmt.Sprintf("scanner %q has no completed report", dc.ToolName),
		}, nil
	}
	reportID := report.ID
	// If the finding is still observed in the latest completed report, it is
	// by definition not fixed — return present before any temporal check.
	present, err := u.deps.Stores.Findings.HasOccurrence(ctx, fid.String(), report.ID)
	if err != nil {
		return nil, fmt.Errorf("check occurrence: %w", err)
	}
	if present {
		return &VerifyResponse{
			FindingID: fid.String(), Outcome: VerifyPresent, ReportID: &reportID,
			Detail: "finding still observed in the latest completed report",
		}, nil
	}
	// Absence can only verify a fix when the report postdates the last
	// observation and covers the full scan scope.
	if !report.CreatedAt.After(f.LastSeenAt) {
		return &VerifyResponse{
			FindingID: fid.String(), Outcome: VerifyInconclusive, ReportID: &reportID,
			Detail: "latest completed report predates the last observation",
		}, nil
	}
	if report.Completeness != "complete" {
		return &VerifyResponse{
			FindingID: fid.String(), Outcome: VerifyInconclusive, ReportID: &reportID,
			Detail: fmt.Sprintf("latest report scope is %q, not complete", report.Completeness),
		}, nil
	}

	if _, err := u.deps.Stores.Findings.MarkFixed(ctx, fid.String()); err != nil {
		return nil, fmt.Errorf("mark fixed: %w", err)
	}
	changes, _ := json.Marshal(map[string]any{
		"report_id":  report.ID,
		"tool":       report.ToolName,
		"branch":     strOrEmpty(report.Branch),
		"commit_sha": strOrEmpty(report.CommitSha),
	})
	if _, err := u.deps.Stores.Findings.CreateEvent(ctx, port.FindingEventInput{
		FindingID: fid.String(),
		EventType: "verified_fixed",
		Changes:   changes,
	}); err != nil {
		return nil, fmt.Errorf("log verification event: %w", err)
	}
	if u.deps.Tracker != nil {
		u.deps.Tracker.Dispatch(ctx, tracker.Event{
			Type:         tracker.EventVerifiedFixed,
			FindingID:    fid.String(),
			Severity:     f.CurrentSeverity,
			SeverityRank: f.CurrentSeverityRank,
			Title:        f.CurrentTitle,
			Fingerprint:  f.Fingerprint,
			FindingKind:  f.FindingKind,
			OccurredAt:   time.Now(),
		})
	}
	return &VerifyResponse{
		FindingID: fid.String(), Outcome: VerifyFixed, ReportID: &reportID,
		Detail: fmt.Sprintf("finding absent from completed %s report %s", report.ToolName, shortID(report.ID)),
	}, nil
}

func strOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}
