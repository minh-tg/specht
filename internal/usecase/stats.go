package usecase

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/minh-tg/specht/internal/aging"
	"github.com/minh-tg/specht/internal/port"
)

// SeverityCount is one severity bucket of a project's finding breakdown.
type SeverityCount struct {
	Severity      string `json:"severity"`
	Count         int32  `json:"count"`
	BlockingCount int32  `json:"blocking_count"`
}

// AnalysisStateCount is one analysis-state bucket of a project's finding
// breakdown.
type AnalysisStateCount struct {
	State string `json:"state"`
	Count int32  `json:"count"`
}

// ProjectStats is a project's aggregate finding/waiver/report statistics.
type ProjectStats struct {
	TotalFindings int32 `json:"total_findings"`
	BlockingCount int32 `json:"blocking_count"`
	WaiverCount   int32 `json:"waiver_count"`
	// PendingWaiverCount is the number of waiver requests waiting for a
	// decision. They do not count in the gate until approved.
	PendingWaiverCount int32                `json:"pending_waiver_count"`
	ReportCount        int32                `json:"report_count"`
	BySeverity         []SeverityCount      `json:"by_severity"`
	ByAnalysisState    []AnalysisStateCount `json:"by_analysis_state"`
	LatestReport       *ReportResponse      `json:"latest_report,omitempty"`
}

func (u *Usecases) GetProjectStats(ctx context.Context, projectSlug string) (*ProjectStats, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectMember(ctx, project.ID); err != nil {
		return nil, err
	}

	rows, err := u.deps.Stores.Stats.GetProjectStats(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get stats: %w", err)
	}

	stateRows, err := u.deps.Stores.Stats.GetProjectAnalysisStateCounts(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get analysis state counts: %w", err)
	}

	waiverCount, err := u.deps.Stores.Stats.GetProjectWaiverCount(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get waiver count: %w", err)
	}

	pendingWaiverCount, err := u.deps.Stores.Stats.GetProjectPendingWaiverCount(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get pending waiver count: %w", err)
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

	// Blocking comes from the gate itself: the policy floor, source policy,
	// reachability exemptions and waivers all decide what blocks, and only the
	// gate applies them.
	decision, _, err := u.evaluateProjectGate(ctx, project, 0)
	if err != nil {
		return nil, err
	}

	var totalFindings int32
	var totalBlocking int32
	sevCounts := make([]SeverityCount, len(rows))
	for i, r := range rows {
		blocking := int32(decision.BlockingByRank[r.Rank])
		totalFindings += r.Count
		totalBlocking += blocking
		sevCounts[i] = SeverityCount{
			Severity:      r.Severity,
			Count:         r.Count,
			BlockingCount: blocking,
		}
	}

	stateCounts := make([]AnalysisStateCount, len(stateRows))
	for i, r := range stateRows {
		stateCounts[i] = AnalysisStateCount{
			State: r.State,
			Count: r.Count,
		}
	}

	return &ProjectStats{
		TotalFindings:      totalFindings,
		BlockingCount:      totalBlocking,
		WaiverCount:        waiverCount,
		PendingWaiverCount: pendingWaiverCount,
		ReportCount:        reportCount,
		BySeverity:         sevCounts,
		ByAnalysisState:    stateCounts,
		LatestReport:       latest,
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
	// Truncated is true when the project has more open findings than the
	// report evaluates (port.MaxAgingRows, oldest first), so the bucket and
	// overdue numbers cover only the oldest ones.
	Truncated bool `json:"truncated"`
}

// maxOverdueListed caps the overdue detail list; OverdueTotal is uncapped.
const maxOverdueListed = 100

// GetAging returns the aging/SLA snapshot for a project: bucket counts with
// overdue subsets, the oldest overdue findings, ever-reopened count, and
// new findings per week over the trailing 12 weeks.
func (u *Usecases) GetAging(ctx context.Context, projectSlug string) (*AgingResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectMember(ctx, project.ID); err != nil {
		return nil, err
	}
	rows, truncated, err := u.deps.Stores.Stats.GetAgingRows(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("get aging rows: %w", err)
	}
	now := time.Now().UTC()
	weekly, err := u.deps.Stores.Stats.GetNewFindingCounts(ctx, project.ID, trendStart(now))
	if err != nil {
		return nil, fmt.Errorf("get new finding counts: %w", err)
	}
	resp := AssembleAging(rows, weekly, now)
	resp.Truncated = truncated
	return resp, nil
}

// trendWeeks is how many weeks the new-findings trend covers.
const trendWeeks = 12

// trendStart is the Monday the trend window begins on.
func trendStart(now time.Time) time.Time {
	return weekStart(now).AddDate(0, 0, -7*(trendWeeks-1))
}

// agingOverdue is one overdue row accumulated while classifying.
type agingOverdue struct {
	row port.AgingRow
	age int
	sla int
	due time.Time
}

// tallyAgingRow folds one classified row into the bucket, overdue, reopened,
// and weekly counters.
func tallyAgingRow(
	resp *AgingResponse,
	buckets map[string]*AgingBucketCount,
	overdueRows *[]agingOverdue,
	row port.AgingRow,
	c aging.Classification,
) {
	b := buckets[c.Bucket]
	b.Count++
	if c.Overdue {
		b.Overdue++
		resp.OverdueTotal++
		*overdueRows = append(*overdueRows, agingOverdue{row: row, age: c.AgeDays, sla: c.SLADays, due: c.DueDate})
	}
	if row.Reopened {
		resp.Reopened++
	}
}

// AssembleAging folds the open findings' aging rows and the weekly count of
// new findings into a response at now. Only open and reopened rows are
// tallied, so the buckets always describe open risk whatever the source hands
// in. Pure, so tests and callers can pin exact snapshots.
func AssembleAging(rows []port.AgingRow, weekly []port.WeeklyCount, now time.Time) *AgingResponse {
	now = now.UTC()
	buckets := map[string]*AgingBucketCount{}
	order := []string{aging.BucketNew, aging.BucketAging, aging.BucketStale, aging.BucketDebt}
	for _, b := range order {
		buckets[b] = &AgingBucketCount{Bucket: b}
	}
	resp := &AgingResponse{}
	var overdueRows []agingOverdue
	weeks := map[string]int32{}
	weekKeys := make([]string, 0, trendWeeks)
	monday := weekStart(now)
	for i := trendWeeks - 1; i >= 0; i-- {
		key := monday.AddDate(0, 0, -7*i).Format("2006-01-02")
		weekKeys = append(weekKeys, key)
		weeks[key] = 0
	}
	for _, w := range weekly {
		if _, ok := weeks[w.WeekStart]; ok {
			weeks[w.WeekStart] = w.Count
		}
	}
	for _, row := range rows {
		if !aging.OpenState(row.State) {
			continue
		}
		c := aging.Classify(row.FirstSeen, now, row.SeverityRank, row.State, row.Reopened)
		tallyAgingRow(resp, buckets, &overdueRows, row, c)
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
