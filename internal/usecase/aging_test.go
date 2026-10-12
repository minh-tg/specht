package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/aging"
	"github.com/minh-tg/specht/internal/port"
)

type mockStatsRepo struct {
	port.StatsStore
	rows      []port.AgingRow
	truncated bool
	weekly    []port.WeeklyCount
	err       error
}

func (m *mockStatsRepo) GetAgingRows(ctx context.Context, projectID string) ([]port.AgingRow, bool, error) {
	if m.err != nil {
		return nil, false, m.err
	}
	return m.rows, m.truncated, nil
}

func (m *mockStatsRepo) GetNewFindingCounts(context.Context, string, time.Time) ([]port.WeeklyCount, error) {
	return m.weekly, nil
}

func TestAssembleAging_BucketsAndOverdue(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	days := func(n int) time.Time { return now.AddDate(0, 0, -n) }
	rows := []port.AgingRow{
		{ID: "new-critical", Title: "CVE-1", Severity: "critical", SeverityRank: 4, FirstSeen: days(2), State: "open"},
		{ID: "old-critical", Title: "CVE-2", Severity: "critical", SeverityRank: 4, FirstSeen: days(40), State: "open", Reopened: true},
		{ID: "old-low", Title: "CVE-3", Severity: "low", SeverityRank: 1, FirstSeen: days(100), State: "reopened"},
	}
	resp := AssembleAging(rows, nil, now)
	require.Len(t, resp.Buckets, 4)
	byBucket := map[string]AgingBucketCount{}
	for _, b := range resp.Buckets {
		byBucket[b.Bucket] = b
	}
	assert.Equal(t, int32(1), byBucket[aging.BucketNew].Count)
	assert.Equal(t, int32(1), byBucket[aging.BucketStale].Count)
	assert.Equal(t, int32(1), byBucket[aging.BucketDebt].Count)
	assert.Equal(t, int32(1), byBucket[aging.BucketStale].Overdue, "40d critical past 7d SLA")
	assert.Equal(t, int32(0), byBucket[aging.BucketDebt].Overdue, "100d low within 180d SLA")
	assert.Equal(t, int32(1), resp.OverdueTotal)
	require.Len(t, resp.Overdue, 1)
	assert.Equal(t, "old-critical", resp.Overdue[0].ID)
	assert.True(t, resp.Overdue[0].Reopened)
	assert.Equal(t, int32(1), resp.Reopened)
	assert.False(t, resp.Truncated)
}

// The buckets describe open risk. A closed finding that reaches the assembler
// is left out, whichever store handed it over.
func TestAssembleAging_LeavesOutClosedFindings(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	rows := []port.AgingRow{
		{ID: "open", SeverityRank: 3, FirstSeen: now.AddDate(0, 0, -3), State: "open"},
		{ID: "fixed-ancient", SeverityRank: 4, FirstSeen: now.AddDate(0, 0, -400), State: "fixed", Reopened: true},
		{ID: "archived", SeverityRank: 4, FirstSeen: now.AddDate(0, 0, -400), State: "archived"},
	}

	resp := AssembleAging(rows, nil, now)

	var total int32
	for _, b := range resp.Buckets {
		total += b.Count
	}
	assert.Equal(t, int32(1), total)
	assert.Zero(t, resp.OverdueTotal)
	assert.Zero(t, resp.Reopened, "a closed finding's reopen history is not open work")
}

func TestAssembleAging_NewPerWeekComesFromTheWeeklyCounts(t *testing.T) {
	// Friday 2026-09-04 (week starts Mon 2026-08-31).
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	weekly := []port.WeeklyCount{
		{WeekStart: "2026-08-31", Count: 1},
		{WeekStart: "2026-08-24", Count: 2},
		{WeekStart: "2020-01-06", Count: 50},
	}

	resp := AssembleAging(nil, weekly, now)

	require.Len(t, resp.NewPerWeek, 12)
	byWeek := map[string]int32{}
	for _, w := range resp.NewPerWeek {
		byWeek[w.Week] = w.Count
	}
	assert.Equal(t, int32(1), byWeek["2026-08-31"])
	assert.Equal(t, int32(2), byWeek["2026-08-24"])
	assert.Equal(t, int32(0), byWeek["2026-08-17"])
	assert.Equal(t, "2026-08-31", resp.NewPerWeek[11].Week, "the current week is last")
	var total int32
	for _, w := range resp.NewPerWeek {
		total += w.Count
	}
	assert.Equal(t, int32(3), total, "weeks outside the trend window are ignored")
}

func TestTrendStart_IsTheMondayOfTheOldestTrendWeek(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	resp := AssembleAging(nil, nil, now)
	assert.Equal(t, resp.NewPerWeek[0].Week, trendStart(now).Format("2006-01-02"))
}

func TestGetAging_ReportsTruncation(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(context.Context, string) (port.Project, error) { return makeProject(true), nil }
	sr := &mockStatsRepo{truncated: true}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Stats: sr}})

	resp, err := uc.GetAging(adminCtx(), "my-app")

	require.NoError(t, err)
	assert.True(t, resp.Truncated)
}

func TestGetAging_Success(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	now := time.Now().UTC()
	sr := &mockStatsRepo{rows: []port.AgingRow{
		{ID: "f1", Title: "CVE-1", Severity: "high", SeverityRank: 3, FirstSeen: now.AddDate(0, 0, -60), State: "open"},
	}}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Stats: sr}})
	resp, err := uc.GetAging(adminCtx(), "my-app")
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.OverdueTotal, "60d high past 30d SLA")
	require.Len(t, resp.Overdue, 1)
	assert.Equal(t, "f1", resp.Overdue[0].ID)
}
