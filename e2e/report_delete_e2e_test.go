//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_DeleteReportArchivesItsOnlyEvidence walks the story behind report
// delete: a scan was uploaded by mistake, an admin removes it, and the
// findings that only it showed stop blocking without disappearing. A later
// scan that sees them again opens them afresh.
func TestE2E_DeleteReportArchivesItsOnlyEvidence(t *testing.T) {
	slug := newProject(t, "reportdel")
	key := mintKey(t, slug)
	report := ingestFixture(t, slug, key, "high-medium.sarif.json")
	require.Equal(t, 2, report.TotalFindings)
	require.True(t, getGate(t, slug, "").ThresholdBreached, "the high finding blocks before the delete")

	reportPath := "/api/v1/projects/" + slug + "/reports/" + report.ReportID

	t.Run("a project outsider cannot delete it", func(t *testing.T) {
		outsider := request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": "e2e-viewer@example.com", "password": adminPass}, http.StatusOK)
		status, _ := doJSON(t, http.MethodDelete, reportPath, outsider.Token, nil)
		require.Equal(t, http.StatusForbidden, status)
		status, _ = doJSON(t, http.MethodDelete, reportPath, key, nil)
		require.Contains(t, []int{http.StatusForbidden, http.StatusUnauthorized}, status, "an API key never deletes reports")
	})

	t.Run("a malformed or unknown id is refused", func(t *testing.T) {
		status, _ := doJSON(t, http.MethodDelete, "/api/v1/projects/"+slug+"/reports/not-a-uuid", adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status)
		status, _ = doJSON(t, http.MethodDelete, "/api/v1/projects/"+slug+"/reports/00000000-0000-4000-8000-00000000dead", adminToken, nil)
		require.Equal(t, http.StatusNotFound, status)
	})

	t.Run("the admin deletes it", func(t *testing.T) {
		req, err := http.NewRequest(http.MethodDelete, baseURL+reportPath, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		require.Equal(t, http.StatusNoContent, resp.StatusCode)
		require.Equal(t, "2", resp.Header.Get("X-Archived-Findings"))
	})

	t.Run("the findings no longer count, block or show by default", func(t *testing.T) {
		stats := readStats(t, slug, adminToken, http.StatusOK)
		require.Zero(t, stats.TotalFindings)
		require.Zero(t, stats.BlockingCount)
		require.Zero(t, stats.ReportCount)
		require.False(t, getGate(t, slug, "").ThresholdBreached, "nothing blocks once the evidence is gone")
		require.Empty(t, listFindings(t, slug))
		aging := readAging(t, slug, adminToken, http.StatusOK)
		for _, b := range aging.Buckets {
			require.Zero(t, b.Count)
		}
	})

	t.Run("they stay readable when asked for", func(t *testing.T) {
		archived := listFindingsPage(t, slug, "status=archived&limit=50")
		require.Len(t, archived, 2)
		for _, f := range archived {
			require.Equal(t, "archived", f.State)
		}
		one := request[findingResponse](t, http.MethodGet, "/api/v1/findings/"+archived[0].ID, adminToken, nil, http.StatusOK)
		require.Equal(t, archived[0].ID, one.ID)
	})

	t.Run("deleting twice reports not found", func(t *testing.T) {
		status, _ := doJSON(t, http.MethodDelete, reportPath, adminToken, nil)
		require.Equal(t, http.StatusNotFound, status)
	})

	t.Run("a later scan opens the findings again", func(t *testing.T) {
		again := ingestFixture(t, slug, key, "high-medium.sarif.json")
		require.Equal(t, 2, again.TotalFindings)
		require.EqualValues(t, 2, readStats(t, slug, adminToken, http.StatusOK).TotalFindings)
		require.True(t, getGate(t, slug, "").ThresholdBreached)
		require.Len(t, listFindings(t, slug), 2)
	})
}
