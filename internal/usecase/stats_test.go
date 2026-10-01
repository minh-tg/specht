package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

type mockStatsStore struct {
	port.StatsStore
	severity    []port.SeverityStat
	analysis    []port.AnalysisStateStat
	severityErr error
	analysisErr error
}

func (m *mockStatsStore) GetProjectStats(context.Context, string) ([]port.SeverityStat, error) {
	if m.severityErr != nil {
		return nil, m.severityErr
	}
	return m.severity, nil
}

func (m *mockStatsStore) GetProjectAnalysisStateCounts(context.Context, string) ([]port.AnalysisStateStat, error) {
	if m.analysisErr != nil {
		return nil, m.analysisErr
	}
	return m.analysis, nil
}

func (m *mockStatsStore) GetProjectWaiverCount(context.Context, string) (int32, error) { return 0, nil }

func (m *mockStatsStore) GetProjectReportCount(context.Context, string) (int32, error) { return 0, nil }

func (m *mockStatsStore) GetProjectLatestReport(context.Context, string) (port.Report, error) {
	return port.Report{}, port.ErrNotFound
}

func statsUsecase(store *mockStatsStore) *Usecases {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(context.Context, string) (port.Project, error) {
		return makeProject(true), nil
	}
	return New(Deps{Stores: &port.Stores{Projects: pr, Stats: store}})
}

func TestGetProjectStats_ByAnalysisState(t *testing.T) {
	store := &mockStatsStore{
		severity: []port.SeverityStat{{Severity: "high", Count: 2, BlockingCount: 1}},
		analysis: []port.AnalysisStateStat{
			{State: "exploitable", Count: 1},
			{State: "unanalyzed", Count: 1},
		},
	}
	stats, err := statsUsecase(store).GetProjectStats(context.Background(), "my-app")
	require.NoError(t, err)
	assert.Equal(t, int32(2), stats.TotalFindings)
	assert.Equal(t, []AnalysisStateCount{
		{State: "exploitable", Count: 1},
		{State: "unanalyzed", Count: 1},
	}, stats.ByAnalysisState)
}

func TestGetProjectStats_EmptyProjectMarshalAnalysisStates(t *testing.T) {
	stats, err := statsUsecase(&mockStatsStore{}).GetProjectStats(context.Background(), "my-app")
	require.NoError(t, err)
	require.NotNil(t, stats.ByAnalysisState, "an empty project still reports an array, never null")
	assert.Empty(t, stats.ByAnalysisState)

	raw, err := json.Marshal(stats)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"by_analysis_state":[]`)
	assert.NotContains(t, string(raw), `"by_analysis_state":null`)
}

func TestGetProjectStats_AnalysisStateError(t *testing.T) {
	store := &mockStatsStore{analysisErr: errors.New("boom")}
	_, err := statsUsecase(store).GetProjectStats(context.Background(), "my-app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get analysis state counts")
}
