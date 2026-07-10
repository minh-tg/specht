package usecase

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/xMinhx/specht/internal/db/sqlc"
)

type SeverityCount struct {
	Severity      string `json:"severity"`
	Count         int32  `json:"count"`
	BlockingCount int32  `json:"blocking_count"`
}

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

	latestReport, err := u.deps.Repos.Stats.GetProjectLatestReport(ctx, project.ID)
	if err != nil {
		slog.Warn("get latest report for stats", "project", projectSlug, "error", err)
		latestReport = sqlc.Report{}
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

	var latest *ReportResponse
	if latestReport.ID.Valid {
		r := toReport(latestReport)
		latest = &r
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
