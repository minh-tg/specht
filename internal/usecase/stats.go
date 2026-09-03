package usecase

import (
	"context"
	"fmt"
	"log/slog"
)

// SeverityCount is one severity bucket of a project's finding breakdown.
type SeverityCount struct {
	Severity      string `json:"severity"`
	Count         int32  `json:"count"`
	BlockingCount int32  `json:"blocking_count"`
}

// ProjectStats is a project's aggregate finding/waiver/report statistics.
type ProjectStats struct {
	TotalFindings int32           `json:"total_findings"`
	BlockingCount int32           `json:"blocking_count"`
	WaiverCount   int32           `json:"waiver_count"`
	ReportCount   int32           `json:"report_count"`
	BySeverity    []SeverityCount `json:"by_severity"`
	LatestReport  *ReportResponse `json:"latest_report,omitempty"`
}

func (u *Usecases) GetProjectStats(ctx context.Context, projectSlug string) (*ProjectStats, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}

	rows, err := u.deps.Repos.Stats.GetProjectStats(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get stats: %w", err)
	}

	waiverCount, err := u.deps.Repos.Stats.GetProjectWaiverCount(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get waiver count: %w", err)
	}

	reportCount, err := u.deps.Repos.Stats.GetProjectReportCount(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get report count: %w", err)
	}

	var latest *ReportResponse
	latestRow, err := u.deps.Repos.Stats.GetProjectLatestReport(ctx, project.ID)
	if err != nil {
		slog.Warn("get latest report for stats", "project", projectSlug, "error", err)
	} else if latestRow.ID.Valid {
		r := ReportResponse{
			ID:            uuidStr(latestRow.ID),
			ProjectID:     uuidStr(latestRow.ProjectID),
			ToolName:      latestRow.ToolName,
			ToolVersion:   strOpt(latestRow.ToolVersion),
			ScanType:      latestRow.ScanType,
			ScanTarget:    strOpt(latestRow.ScanTarget),
			Status:        latestRow.Status,
			TotalFindings: intOpt(latestRow.TotalFindings),
			Branch:        strOpt(latestRow.Branch),
			CommitSha:     strOpt(latestRow.CommitSha),
			CreatedAt:     timePtr(latestRow.CreatedAt),
			CompletedAt:   timeOpt(latestRow.CompletedAt),
		}
		latest = &r
	}

	var totalFindings int32
	var totalBlocking int32
	sevCounts := make([]SeverityCount, len(rows))
	for i, r := range rows {
		totalFindings += r.Count
		totalBlocking += r.BlockingCount
		sevCounts[i] = SeverityCount{
			Severity:      r.Severity,
			Count:         r.Count,
			BlockingCount: r.BlockingCount,
		}
	}

	return &ProjectStats{
		TotalFindings: totalFindings,
		BlockingCount: totalBlocking,
		WaiverCount:   waiverCount,
		ReportCount:   reportCount,
		BySeverity:    sevCounts,
		LatestReport:  latest,
	}, nil
}
