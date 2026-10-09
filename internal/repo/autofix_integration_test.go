//go:build integration

package repo

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/parser"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/usecase"
)

// TestAutoFix_ClosesAcrossCommitsOnSameBranch runs the scan-equivalence
// auto-fix against real Postgres. A full scan of a later commit on the same
// branch closes a finding the earlier commit observed; a full scan of another
// branch does not.
func TestAutoFix_ClosesAcrossCommitsOnSameBranch(t *testing.T) {
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

	raw, err := os.ReadFile("../parser/trivy/testdata/multi-type-scan.json")
	require.NoError(t, err)
	// The same scan with the lodash vulnerability removed, as after a fix.
	fixedRaw, err := rewriteTrivyReport(raw, func(results []map[string]any) {
		for _, r := range results {
			if class, _ := r["Class"].(string); class == "lang-pkgs" {
				r["Vulnerabilities"] = []any{}
			}
		}
	})
	require.NoError(t, err)

	project, err := stores.Projects.GetBySlug(ctx, "my-app")
	require.NoError(t, err)
	lodashState := func(t *testing.T) string {
		t.Helper()
		findings, err := stores.Findings.ListByProject(ctx, project.ID, port.ListFindingsParams{Limit: 100})
		require.NoError(t, err)
		id := findingIDFor(findings, "lodash")
		require.NotEmpty(t, id, "lodash finding must exist from the first scan")
		f, err := stores.Findings.GetByID(ctx, id)
		require.NoError(t, err)
		return f.State
	}

	first, err := uc.IngestReport(ctx, usecase.IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: raw,
		Branch: "main", CommitSha: "aaa111",
	})
	require.NoError(t, err)
	require.Equal(t, 4, first.TotalFindings)
	assert.Equal(t, "open", lodashState(t))

	// A full scan of another branch that lacks the finding proves nothing
	// about main, so main's finding stays open.
	_, err = uc.IngestReport(ctx, usecase.IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: fixedRaw,
		Branch: "feature/x", CommitSha: "ccc333",
	})
	require.NoError(t, err)
	assert.Equal(t, "open", lodashState(t), "a full scan of another branch must not close the finding")

	// A full scan of a later main commit that no longer observes the finding
	// closes it. The appended comment changes the raw hash so the duplicate
	// guard does not reject the second copy of the same content.
	laterRaw, err := appendComment(fixedRaw, "later-main-commit")
	require.NoError(t, err)
	_, err = uc.IngestReport(ctx, usecase.IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: laterRaw,
		Branch: "main", CommitSha: "bbb222",
	})
	require.NoError(t, err)
	assert.Equal(t, "fixed", lodashState(t), "a full scan of a later commit on the same branch must close the finding")
}
