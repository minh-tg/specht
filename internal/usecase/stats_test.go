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
	pending     int32
}

// gateRows is what the fake finding store offers the gate as blocking
// candidates. The fake filters by the floor it is asked for, as the query does.
type gateRows struct {
	candidates []port.GateCandidate
	err        error
	askedFloor int16
}

func (g *gateRows) list(_ context.Context, _ string, minRank int16) ([]port.GateCandidate, error) {
	g.askedFloor = minRank
	if g.err != nil {
		return nil, g.err
	}
	var out []port.GateCandidate
	for _, c := range g.candidates {
		if c.CurrentSeverityRank >= minRank {
			out = append(out, c)
		}
	}
	return out, nil
}

func blocker(id string, rank int16) port.GateCandidate {
	f := makeFindingRow(1)
	f.ID = id
	f.CurrentSeverityRank = rank
	return port.GateCandidate{Finding: f}
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

func (m *mockStatsStore) GetProjectPendingWaiverCount(context.Context, string) (int32, error) {
	return m.pending, nil
}

func (m *mockStatsStore) GetProjectReportCount(context.Context, string) (int32, error) { return 0, nil }

func (m *mockStatsStore) GetProjectLatestReport(context.Context, string) (port.Report, error) {
	return port.Report{}, port.ErrNotFound
}

func statsUsecase(store *mockStatsStore) *Usecases {
	return statsUsecaseWithGate(store, &gateRows{})
}

func statsUsecaseWithGate(store *mockStatsStore, rows *gateRows) *Usecases {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(context.Context, string) (port.Project, error) {
		return makeProject(true), nil
	}
	fr := &mockFindingRepo{listGateCandidatesFn: rows.list}
	return New(Deps{Stores: &port.Stores{Projects: pr, Stats: store, Findings: fr, Waivers: &mockWaiverRepo{}}})
}

func TestGetProjectStats_ByAnalysisState(t *testing.T) {
	store := &mockStatsStore{
		severity: []port.SeverityStat{{Severity: "high", Rank: 3, Count: 2}},
		analysis: []port.AnalysisStateStat{
			{State: "exploitable", Count: 1},
			{State: "unanalyzed", Count: 1},
		},
	}
	stats, err := statsUsecase(store).GetProjectStats(adminCtx(), "my-app")
	require.NoError(t, err)
	assert.Equal(t, int32(2), stats.TotalFindings)
	assert.Equal(t, []AnalysisStateCount{
		{State: "exploitable", Count: 1},
		{State: "unanalyzed", Count: 1},
	}, stats.ByAnalysisState)
}

func TestGetProjectStats_EmptyProjectMarshalAnalysisStates(t *testing.T) {
	stats, err := statsUsecase(&mockStatsStore{}).GetProjectStats(adminCtx(), "my-app")
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
	_, err := statsUsecase(store).GetProjectStats(adminCtx(), "my-app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get analysis state counts")
}

func TestGetProjectStats_PendingWaiverCount(t *testing.T) {
	stats, err := statsUsecase(&mockStatsStore{pending: 3}).GetProjectStats(adminCtx(), "my-app")
	require.NoError(t, err)
	assert.Equal(t, int32(3), stats.PendingWaiverCount)
	assert.Equal(t, int32(0), stats.WaiverCount, "pending requests do not count as waivers")

	raw, err := json.Marshal(stats)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"pending_waiver_count":3`)
}

func TestGetProjectStats_BlockingComesFromTheGate(t *testing.T) {
	store := &mockStatsStore{severity: []port.SeverityStat{
		{Severity: "low", Rank: 1, Count: 4},
		{Severity: "high", Rank: 3, Count: 2},
		{Severity: "critical", Rank: 4, Count: 3},
	}}
	rows := &gateRows{candidates: []port.GateCandidate{
		blocker("c1", 4), blocker("c2", 4), blocker("h1", 3), blocker("l1", 1),
	}}

	stats, err := statsUsecaseWithGate(store, rows).GetProjectStats(adminCtx(), "my-app")

	require.NoError(t, err)
	assert.Equal(t, int32(9), stats.TotalFindings, "every open finding counts")
	byName := map[string]SeverityCount{}
	for _, s := range stats.BySeverity {
		byName[s.Severity] = s
	}
	assert.Equal(t, int32(2), byName["critical"].BlockingCount)
	assert.Equal(t, int32(1), byName["high"].BlockingCount)
	assert.Equal(t, int32(0), byName["low"].BlockingCount, "below the policy floor, so the gate lets it through")
	assert.Equal(t, int32(3), stats.BlockingCount)
	assert.Positive(t, rows.askedFloor, "the gate is asked with the policy floor")
}

func TestGetProjectStats_GateFailureIsAnError(t *testing.T) {
	store := &mockStatsStore{severity: []port.SeverityStat{{Severity: "high", Rank: 3, Count: 1}}}
	_, err := statsUsecaseWithGate(store, &gateRows{err: errors.New("boom")}).GetProjectStats(adminCtx(), "my-app")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gate eval")
}
