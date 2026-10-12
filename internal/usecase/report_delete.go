package usecase

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

var (
	// ErrReportNotFound is returned when the report is not in the project.
	ErrReportNotFound = errors.New("report not found")
	// ErrReportProcessing is returned while a scan is still writing the report.
	ErrReportProcessing = port.ErrReportProcessing
)

// ReportDeleteResponse says what deleting a report changed.
type ReportDeleteResponse struct {
	// ArchivedFindings is how many findings lost their only evidence with the
	// report and are archived now.
	ArchivedFindings int `json:"archived_findings"`
}

// DeleteReport removes a report from a project. Findings that only that
// report showed are archived, so they stop blocking with nothing left to
// explain them; findings it introduced are attributed to the earliest report
// that still shows them. Needs the project admin role.
func (u *Usecases) DeleteReport(ctx context.Context, projectSlug, reportID string) (*ReportDeleteResponse, error) {
	id, err := validID(reportID)
	if err != nil {
		return nil, err
	}
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrProjectAccessDenied
		}
		return nil, fmt.Errorf("lookup project: %w", err)
	}
	if err := u.requireProjectAdmin(ctx, project.ID); err != nil {
		return nil, err
	}
	actor := auth.ContextIdentity(ctx).UserID

	result, err := u.deps.Stores.Reports.DeleteReportAndSettle(ctx, id, project.ID, &actor)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrReportNotFound
		}
		if errors.Is(err, port.ErrReportProcessing) {
			return nil, ErrReportProcessing
		}
		return nil, fmt.Errorf("delete report: %w", err)
	}
	slog.Info("report deleted", "project", projectSlug, "report_id", id, "archived_findings", result.ArchivedFindings)
	return &ReportDeleteResponse{ArchivedFindings: result.ArchivedFindings}, nil
}
