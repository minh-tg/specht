//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestReportListFilters(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	other := createTestProject(t, repos)

	create := func(projectID pgtype.UUID, branch, commit string) string {
		t.Helper()
		report, err := repos.Reports.Create(ctx, CreateReportParams{
			ProjectID: projectID, ToolName: "trivy", ScanType: "image", ScanScope: []byte(`{}`),
			Branch:    pgtype.Text{String: branch, Valid: branch != ""},
			CommitSha: pgtype.Text{String: commit, Valid: commit != ""},
		})
		require.NoError(t, err)
		return toUUID(report.ID)
	}
	first := create(project.ID, "main", "aaaaaaa1")
	second := create(project.ID, "feature/refund-retry", "bbbbbbb2")
	third := create(project.ID, "feature/refund-retry", "ccccccc3")
	create(project.ID, "", "")
	create(other.ID, "feature/refund-retry", "bbbbbbb2")

	list := func(filter port.ReportFilter) []string {
		t.Helper()
		rows, err := repos.Reports.ListByProject(ctx, project.ID, filter, 50, 0)
		require.NoError(t, err)
		ids := make([]string, len(rows))
		for i, r := range rows {
			ids[i] = toUUID(r.ID)
		}
		return ids
	}

	assert.Len(t, list(port.ReportFilter{}), 4, "no filter returns every report, including those without a branch")
	assert.Equal(t, []string{first}, list(port.ReportFilter{Branch: "main"}))
	assert.Equal(t, []string{third, second}, list(port.ReportFilter{Branch: "feature/refund-retry"}), "newest first")
	assert.Equal(t, []string{second}, list(port.ReportFilter{CommitSha: "bbbbbbb2"}), "another project's report with the same commit is not returned")
	assert.Equal(t, []string{third}, list(port.ReportFilter{Branch: "feature/refund-retry", CommitSha: "ccccccc3"}))
	assert.Empty(t, list(port.ReportFilter{Branch: "main", CommitSha: "bbbbbbb2"}), "both filters have to match")
	assert.Empty(t, list(port.ReportFilter{Branch: "no-such-branch"}))
	assert.Empty(t, list(port.ReportFilter{CommitSha: "bbbbbbb"}), "abbreviations stay exact unless requested")
	assert.Equal(t, []string{second}, list(port.ReportFilter{CommitSha: "BBBBBBB", CommitPrefix: true}), "prefixes are case-insensitive and project-scoped")
	assert.Empty(t, list(port.ReportFilter{Branch: "main", CommitSha: "bbbbbbb", CommitPrefix: true}), "prefix and branch filters both apply")
	assert.Empty(t, list(port.ReportFilter{CommitSha: "0000000", CommitPrefix: true}))
}
