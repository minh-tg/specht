//go:build integration

package repo

import (
	"context"
	"os"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
)

// TestLatestCompletedInFindingScope_IgnoresNewerOtherScope proves the
// verification basis against real Postgres. A finding is checked against the
// newest completed full report of its own scan scope, even when a newer full
// report of another branch exists.
func TestLatestCompletedInFindingScope_IgnoresNewerOtherScope(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()

	stores := NewPortStores(pool)
	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		require.NoError(t, reg.Register(s))
	}
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: reg})

	creator, err := stores.Users.Create(ctx, "tester@example.com", nil, nil)
	require.NoError(t, err)
	_, err = uc.CreateProject(globalAdminCtx(creator.ID), "My App", "my-app", "validation", creator.ID)
	require.NoError(t, err)
	project, err := stores.Projects.GetBySlug(ctx, "my-app")
	require.NoError(t, err)

	raw, err := os.ReadFile("../parser/trivy/testdata/multi-type-scan.json")
	require.NoError(t, err)
	mainOut, err := uc.IngestReport(ctx, usecase.IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: raw,
		Branch: "main", CommitSha: "aaa111",
	})
	require.NoError(t, err)

	// A newer full scan of another branch, without the lodash finding.
	featureRaw, err := rewriteTrivyReport(raw, func(results []map[string]any) {
		for _, r := range results {
			if class, _ := r["Class"].(string); class == "lang-pkgs" {
				r["Vulnerabilities"] = []any{}
			}
		}
	})
	require.NoError(t, err)
	_, err = uc.IngestReport(ctx, usecase.IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: featureRaw,
		Branch: "feature/x", CommitSha: "ccc333",
	})
	require.NoError(t, err)

	findings, err := stores.Findings.ListByProject(ctx, project.ID, port.ListFindingsParams{Limit: 100})
	require.NoError(t, err)
	lodashID := findingIDFor(findings, "lodash")
	require.NotEmpty(t, lodashID, "lodash finding must exist from the first scan")

	got, err := stores.Reports.LatestCompletedInFindingScope(ctx, project.ID, lodashID)
	require.NoError(t, err)
	assert.Equal(t, mainOut.ReportID, got.ID, "the main-branch report is the finding's scope, not the newer feature scan")
	require.NotNil(t, got.Branch)
	assert.Equal(t, "main", *got.Branch)

	_, err = stores.Reports.LatestCompletedInFindingScope(ctx, project.ID, uuid.NewString())
	assert.ErrorIs(t, err, port.ErrNotFound, "a finding with no observation has no verification basis")
}
