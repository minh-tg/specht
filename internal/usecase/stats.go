package usecase

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/xMinhx/specht/internal/aging"
	"github.com/xMinhx/specht/internal/port"
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
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}

	rows, err := u.deps.Stores.Stats.GetProjectStats(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get stats: %w", err)
	}

	waiverCount, err := u.deps.Stores.Stats.GetProjectWaiverCount(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get waiver count: %w", err)
	}

	reportCount, err := u.deps.Stores.Stats.GetProjectReportCount(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get report count: %w", err)
	}

	var latest *ReportResponse
	latestRow, err := u.deps.Stores.Stats.GetProjectLatestReport(ctx, project.ID)
	if err != nil {
		slog.Warn("get latest report for stats", "project", projectSlug, "error", err)
	} else if latestRow.ID != "" {
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

// AgingBucketCount is one age bucket with its overdue subset.
type AgingBucketCount struct {
	Bucket  string `json:"bucket"`
	Count   int32  `json:"count"`
	Overdue int32  `json:"overdue"`
}

// OverdueFinding is an open finding past its SLA date, oldest first.
type OverdueFinding struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Severity string    `json:"severity"`
	AgeDays  int32     `json:"age_days"`
	SLADays  int32     `json:"sla_days"`
	DueDate  time.Time `json:"due_date"`
	Reopened bool      `json:"reopened"`
}

// WeeklyNew is one week's newly introduced finding count.
type WeeklyNew struct {
	Week  string `json:"week"`
	Count int32  `json:"count"`
}

// AgingResponse is a project's aging, SLA, and trend snapshot. It is
// deterministic for the same rows evaluated at the same instant.
type AgingResponse struct {
	Buckets      []AgingBucketCount `json:"buckets"`
	OverdueTotal int32              `json:"overdue_total"`
	Overdue      []OverdueFinding   `json:"overdue"`
	Reopened     int32              `json:"reopened"`
	NewPerWeek   []WeeklyNew        `json:"new_per_week"`
}

// maxOverdueListed caps the overdue detail list; OverdueTotal is uncapped.
const maxOverdueListed = 100

// GetAging returns the aging/SLA snapshot for a project: bucket counts with
// overdue subsets, the oldest overdue findings, ever-reopened count, and
// new findings per week over the trailing 12 weeks.
func (u *Usecases) GetAging(ctx context.Context, projectSlug string) (*AgingResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}
	rows, err := u.deps.Stores.Stats.GetAgingRows(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get aging rows: %w", err)
	}
	return AssembleAging(rows, time.Now().UTC()), nil
}

// AssembleAging folds aging rows into a response at now. Pure, so tests
// and callers can pin exact snapshots.
func AssembleAging(rows []port.AgingRow, now time.Time) *AgingResponse {
	now = now.UTC()
	buckets := map[string]*AgingBucketCount{}
	order := []string{aging.BucketNew, aging.BucketAging, aging.BucketStale, aging.BucketDebt}
	for _, b := range order {
		buckets[b] = &AgingBucketCount{Bucket: b}
	}
	resp := &AgingResponse{}
	type overdue struct {
		row port.AgingRow
		age int
		sla int
		due time.Time
	}
	var overdueRows []overdue
	weeks := map[string]int32{}
	weekKeys := make([]string, 0, 12)
	monday := weekStart(now)
	for i := 11; i >= 0; i-- {
		key := monday.AddDate(0, 0, -7*i).Format("2006-01-02")
		weekKeys = append(weekKeys, key)
		weeks[key] = 0
	}
	for _, row := range rows {
		c := aging.Classify(row.FirstSeen, now, row.SeverityRank, row.State, row.Reopened)
		b := buckets[c.Bucket]
		b.Count++
		if c.Overdue {
			b.Overdue++
			resp.OverdueTotal++
			overdueRows = append(overdueRows, overdue{row: row, age: c.AgeDays, sla: c.SLADays, due: c.DueDate})
		}
		if row.Reopened {
			resp.Reopened++
		}
		if wk := weekStart(row.FirstSeen.UTC()).Format("2006-01-02"); true {
			if _, ok := weeks[wk]; ok {
				weeks[wk]++
			}
		}
	}
	for _, b := range order {
		resp.Buckets = append(resp.Buckets, *buckets[b])
	}
	sort.Slice(overdueRows, func(i, j int) bool { return overdueRows[i].age > overdueRows[j].age })
	for i, o := range overdueRows {
		if i >= maxOverdueListed {
			break
		}
		resp.Overdue = append(resp.Overdue, OverdueFinding{
			ID: o.row.ID, Title: o.row.Title, Severity: o.row.Severity,
			AgeDays: int32(o.age), SLADays: int32(o.sla),
			DueDate: o.due, Reopened: o.row.Reopened,
		})
	}
	for _, key := range weekKeys {
		resp.NewPerWeek = append(resp.NewPerWeek, WeeklyNew{Week: key, Count: weeks[key]})
	}
	return resp
}

// weekStart returns the Monday 00:00 UTC starting the week containing t.
func weekStart(t time.Time) time.Time {
	t = t.UTC().Truncate(24 * time.Hour)
	wd := int(t.Weekday())
	if wd == 0 {
		wd = 7
	}
	return t.AddDate(0, 0, -(wd - 1))
}
