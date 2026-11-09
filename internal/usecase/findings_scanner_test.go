package usecase

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func scannerListUsecase(t *testing.T, fr *mockFindingRepo) *Usecases {
	t.Helper()
	pr := &mockProjectRepo{getBySlugFn: func(context.Context, string) (port.Project, error) { return makeProject(true), nil }}
	return New(Deps{Stores: &port.Stores{Projects: pr, Findings: fr}})
}

// The scanner filter reaches the page and the count alike, trimmed and in
// lower case like the names reports are stored under.
func TestListFindings_PassesTheScannerFilter(t *testing.T) {
	var page, count []string
	fr := &mockFindingRepo{
		listByProjectFn: func(_ context.Context, _ string, p port.ListFindingsParams) ([]port.Finding, error) {
			page = p.Scanners
			return nil, nil
		},
		countByProjectFn: func(_ context.Context, _ string, p port.ListFindingsParams) (int64, error) {
			count = p.Scanners
			return 0, nil
		},
	}
	_, _, err := scannerListUsecase(t, fr).ListFindings(adminCtx(), "my-app", FindingFilter{Scanners: []string{"Trivy", " semgrep "}}, 20, 0)
	require.NoError(t, err)
	assert.Equal(t, []string{"trivy", "semgrep"}, page)
	assert.Equal(t, page, count)
}

func TestListFindings_RefusesABadScannerFilter(t *testing.T) {
	for name, scanners := range map[string][]string{
		"empty entry": {"trivy", ""},
		"too long":    {strings.Repeat("s", 65)},
		"too many":    make([]string, 33),
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := scannerListUsecase(t, &mockFindingRepo{}).ListFindings(adminCtx(), "my-app", FindingFilter{Scanners: scanners}, 20, 0)
			assert.ErrorIs(t, err, ErrInvalidFindingQuery)
		})
	}
}

// Every row names its scanners, and a finding no scanner reported gets an
// empty list rather than null.
func TestListFindings_NamesTheScannersOfEachFinding(t *testing.T) {
	first, second := makeFindingRow(1), makeFindingRow(2)
	fr := &mockFindingRepo{
		listByProjectFn: func(context.Context, string, port.ListFindingsParams) ([]port.Finding, error) {
			return []port.Finding{first, second}, nil
		},
		countByProjectFn: func(context.Context, string, port.ListFindingsParams) (int64, error) { return 2, nil },
		listScannersFn: func() (map[string][]string, error) {
			return map[string][]string{first.ID: {"semgrep", "trivy"}}, nil
		},
	}
	findings, _, err := scannerListUsecase(t, fr).ListFindings(adminCtx(), "my-app", FindingFilter{}, 20, 0)
	require.NoError(t, err)
	require.Len(t, findings, 2)
	assert.Equal(t, []string{"semgrep", "trivy"}, findings[0].Scanners)
	assert.NotNil(t, findings[1].Scanners)
	assert.Empty(t, findings[1].Scanners)
}
