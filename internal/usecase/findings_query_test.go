package usecase

import (
	"context"
	"testing"

	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFindingFilterNormalize(t *testing.T) {
	for _, tc := range []struct {
		name   string
		filter FindingFilter
		want   findingQuery
	}{
		{"defaults", FindingFilter{}, findingQuery{sortKey: "severity", sortDir: "desc"}},
		{"title defaults to ascending", FindingFilter{Sort: "title"}, findingQuery{sortKey: "title", sortDir: "asc"}},
		{"explicit direction wins", FindingFilter{Sort: "first_seen", Dir: "asc"}, findingQuery{sortKey: "first_seen", sortDir: "asc"}},
		{"search is trimmed and escaped", FindingFilter{Search: `  100%_a\b `}, findingQuery{sortKey: "severity", sortDir: "desc", search: `100\%\_a\\b`}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.filter.normalize()
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFindingFilterNormalizeRejectsBadInput(t *testing.T) {
	long := make([]rune, maxFindingSearchLen+1)
	for i := range long {
		long[i] = 'x'
	}
	for name, tc := range map[string]struct {
		filter FindingFilter
		msg    string
	}{
		"unknown sort":           {FindingFilter{Sort: "age"}, "sort must be one of"},
		"unknown direction":      {FindingFilter{Dir: "up"}, "dir must be asc or desc"},
		"unknown analysis state": {FindingFilter{AnalysisStates: []string{"in_triage", "bogus"}}, "analysis_state must be"},
		"search too long":        {FindingFilter{Search: string(long)}, "q is longer"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := tc.filter.normalize()
			require.ErrorIs(t, err, ErrInvalidFindingQuery)
			assert.Contains(t, err.Error(), tc.msg)
		})
	}
}

func TestListFindingsPassesQueryToStore(t *testing.T) {
	var listed, counted port.ListFindingsParams
	fr := &mockFindingRepo{
		listByProjectFn: func(_ context.Context, _ string, p port.ListFindingsParams) ([]port.Finding, error) {
			listed = p
			return nil, nil
		},
		countByProjectFn: func(_ context.Context, _ string, p port.ListFindingsParams) (int64, error) {
			counted = p
			return 0, nil
		},
	}
	pr := &mockProjectRepo{getBySlugFn: func(context.Context, string) (port.Project, error) { return makeProject(true), nil }}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Findings: fr}})

	_, _, err := uc.ListFindings(adminCtx(), "my-app", FindingFilter{
		AnalysisStates: []string{"unanalyzed", "in_triage"}, Search: "CVE-2025_1", Sort: "first_seen", Dir: "asc",
	}, 20, 40)

	require.NoError(t, err)
	assert.Equal(t, []string{"unanalyzed", "in_triage"}, listed.AnalysisStates)
	assert.Equal(t, `CVE-2025\_1`, listed.Search)
	assert.Equal(t, "first_seen", listed.SortKey)
	assert.Equal(t, "asc", listed.SortDir)
	assert.Equal(t, int32(20), listed.Limit)
	assert.Equal(t, int32(40), listed.Offset)
	assert.Equal(t, listed.AnalysisStates, counted.AnalysisStates, "the count uses the same filters")
	assert.Equal(t, listed.Search, counted.Search)
	assert.Zero(t, counted.Limit)
}

func TestListFindingsRejectsBadQueryBeforeTouchingTheStore(t *testing.T) {
	fr := &mockFindingRepo{}
	pr := &mockProjectRepo{getBySlugFn: func(context.Context, string) (port.Project, error) { return makeProject(true), nil }}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Findings: fr}})

	_, _, err := uc.ListFindings(adminCtx(), "my-app", FindingFilter{Sort: "age"}, 20, 0)

	require.ErrorIs(t, err, ErrInvalidFindingQuery)
}
