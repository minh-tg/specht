package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// blocksGateUsecase records the list and count params, and offers the given
// gate candidates to the project gate.
func blocksGateUsecase(candidates []port.GateCandidate) (*Usecases, *port.ListFindingsParams, *port.ListFindingsParams) {
	var page, count port.ListFindingsParams
	fr := &mockFindingRepo{
		listGateCandidatesFn: func(context.Context, string, int16) ([]port.GateCandidate, error) {
			return candidates, nil
		},
		listByProjectFn: func(_ context.Context, _ string, p port.ListFindingsParams) ([]port.Finding, error) {
			page = p
			return nil, nil
		},
		countByProjectFn: func(_ context.Context, _ string, p port.ListFindingsParams) (int64, error) {
			count = p
			return 0, nil
		},
	}
	pr := &mockProjectRepo{getBySlugFn: func(context.Context, string) (port.Project, error) { return makeProject(true), nil }}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Findings: fr, Waivers: &mockWaiverRepo{}}})
	return uc, &page, &count
}

// The filter asks the same gate the project verdict comes from, and the page
// and the count both keep exactly its blockers.
func TestListFindings_BlocksGateKeepsTheProjectGateBlockers(t *testing.T) {
	first, second := makeFindingRow(1), makeFindingRow(2)
	uc, page, count := blocksGateUsecase([]port.GateCandidate{{Finding: first}, {Finding: second}})

	_, _, err := uc.ListFindings(adminCtx(), "my-app", FindingFilter{BlocksGate: true}, 20, 0)
	require.NoError(t, err)

	status, err := uc.GetGateStatus(adminCtx(), "my-app", 0)
	require.NoError(t, err)
	require.Len(t, status.BlockedBy, 2)
	assert.True(t, page.OnlyIDs)
	assert.ElementsMatch(t, status.BlockedBy, page.IDs)
	assert.Equal(t, page.OnlyIDs, count.OnlyIDs)
	assert.Equal(t, page.IDs, count.IDs)
}

// With nothing blocking, the filter keeps no finding rather than every one.
func TestListFindings_BlocksGateWithNothingBlockingKeepsNone(t *testing.T) {
	uc, page, count := blocksGateUsecase(nil)

	_, _, err := uc.ListFindings(adminCtx(), "my-app", FindingFilter{BlocksGate: true}, 20, 0)
	require.NoError(t, err)
	assert.True(t, page.OnlyIDs)
	assert.Empty(t, page.IDs)
	assert.True(t, count.OnlyIDs)
}

func TestListFindings_WithoutBlocksGateFiltersNoIDs(t *testing.T) {
	uc, page, _ := blocksGateUsecase([]port.GateCandidate{{Finding: makeFindingRow(1)}})

	_, _, err := uc.ListFindings(adminCtx(), "my-app", FindingFilter{}, 20, 0)
	require.NoError(t, err)
	assert.False(t, page.OnlyIDs)
	assert.Empty(t, page.IDs)
}
