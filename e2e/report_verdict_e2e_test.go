//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minh-tg/specht/internal/repo"
	"github.com/stretchr/testify/require"
)

func TestE2E_ReportVerdictsRequireCompletedEvidence(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	stores := repo.NewPortStores(pool)
	slug := newProject(t, "report-status")
	key := mintKey(t, slug)
	report := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high.sarif.json", map[string]any{"commit_sha": baseSHA}), http.StatusCreated)
	stored, err := stores.Reports.GetByID(ctx, report.ReportID)
	require.NoError(t, err)

	for _, state := range []string{"processing", "failed", "completed"} {
		t.Run(state, func(t *testing.T) {
			_, err := stores.Reports.UpdateStatus(ctx, report.ReportID, stored.ProjectID, state, 1, nil)
			require.NoError(t, err)
			for _, path := range []string{
				"/api/v1/projects/" + slug + "/gate?introduced_only=true&report_id=" + report.ReportID,
				"/api/v1/projects/" + slug + "/pr-check?commit=" + baseSHA + "&report_id=" + report.ReportID,
			} {
				status, body := doJSON(t, http.MethodGet, path, key, nil)
				if state == "completed" {
					require.Equal(t, http.StatusOK, status, "%s", body)
				} else {
					require.Equal(t, http.StatusConflict, status, "%s", body)
					require.Equal(t, "report_not_completed", errorCode(t, body))
				}
			}
		})
	}
}
