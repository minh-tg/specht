//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Checkov names no target, so its reports used to carry target_id NULL and a
// target-scoped waiver never matched. The repository named in the request is
// stored as the target, and the same scanner without a repository still
// leaves the report untargeted. A target-scoped waiver covers the findings
// once every report that observed them names the target.
func TestE2E_CheckovReportTakesTheRequestRepositoryAsItsTarget(t *testing.T) {
	slug := newProject(t, "repo-target")
	key := mintKey(t, slug)
	raw := readFixture(t, "testdata", "checkov-terraform.json")
	scan := func(extra map[string]any) ingestResponse {
		t.Helper()
		body := map[string]any{"project": slug, "scanner": "checkov", "raw_data": json.RawMessage(raw)}
		for k, v := range extra {
			body[k] = v
		}
		return request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key, body, http.StatusCreated)
	}

	untargeted := scan(map[string]any{"commit_sha": "1111111111111111111111111111111111111111"})
	targets := request[[]targetRow](t, http.MethodGet, "/api/v1/projects/"+slug+"/targets", adminToken, nil, http.StatusOK)
	require.Empty(t, targets, "a request that names no repository leaves the target out")
	before := getGate(t, slug, "")
	require.True(t, before.ThresholdBreached, "the fixture's findings block the gate")

	scan(map[string]any{"commit_sha": "2222222222222222222222222222222222222222", "owner": "github://acme/infra"})
	targets = request[[]targetRow](t, http.MethodGet, "/api/v1/projects/"+slug+"/targets", adminToken, nil, http.StatusOK)
	require.Len(t, targets, 1)
	require.Equal(t, "github://acme/infra", targets[0].Name)
	require.Equal(t, "repo", targets[0].Kind)
	require.Len(t, listFindings(t, slug), 3, "the same findings, not a second set under a new scope")

	request[waiverDetail](t, http.MethodPost, "/api/v1/projects/"+slug+"/waivers", adminToken,
		map[string]any{
			"name":     "infra repo",
			"contexts": []map[string]string{{"target_id": targets[0].ID}},
		}, http.StatusCreated)
	// The first report observed the findings with no target, so a target-scoped waiver must not cover that observation.
	require.True(t, getGate(t, slug, "").ThresholdBreached, "the untargeted observation keeps the findings blocked")

	status, body := doJSON(t, http.MethodDelete, "/api/v1/projects/"+slug+"/reports/"+untargeted.ReportID, adminToken, nil)
	require.Equalf(t, http.StatusNoContent, status, "delete the untargeted report: %s", body)
	require.Len(t, listFindings(t, slug), 3, "the targeted report still observes the findings")
	require.False(t, getGate(t, slug, "").ThresholdBreached, "the target-scoped waiver matches the Checkov findings seen only on the repository")
}
