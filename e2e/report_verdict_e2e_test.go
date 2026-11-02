//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestE2E_ReportVerdictsRequireCompletedEvidence(t *testing.T) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	slug := newProject(t, "report-status")
	key := mintKey(t, slug)
	report := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high.sarif.json", map[string]any{"commit_sha": baseSHA}), http.StatusCreated)

	for _, state := range []string{"processing", "failed", "completed"} {
		t.Run(state, func(t *testing.T) {
			// The status is forced directly: the store only moves a report out
			// of processing, and this test needs each state in turn.
			_, err := pool.Exec(ctx, `UPDATE reports SET status = $2, total_findings = 1 WHERE id = $1`, report.ReportID, state)
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
