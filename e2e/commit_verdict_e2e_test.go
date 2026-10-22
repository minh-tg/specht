//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestE2E_CommitVerdictUsesReportIntroductions(t *testing.T) {
	slug := newProject(t, "commit-verdict")
	key := mintKey(t, slug)
	body := ingestBodyWith(t, slug, "high.sarif.json", map[string]any{
		"commit_sha": baseSHA, "branch": "main",
	})
	var raw map[string]any
	require.NoError(t, json.Unmarshal(body["raw_data"].(json.RawMessage), &raw))
	raw["runs"].([]any)[0].(map[string]any)["results"] = []any{}
	body["raw_data"] = raw
	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key, body, http.StatusCreated)

	for i, branch := range []string{"feature-a", "feature-b"} {
		sha := strings.Repeat(string(rune('2'+i)), 40)
		report := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
			ingestBodyWith(t, slug, "high.sarif.json", map[string]any{
				"commit_sha": sha, "branch": branch, "base_revision": "main", "gate_introduced_only": true,
			}), http.StatusCreated)
		require.Equal(t, 1, report.IntroducedCount)
		require.True(t, report.ThresholdBreached)
		for _, suffix := range []string{"", "&report_id=" + report.ReportID} {
			status, raw := doJSON(t, http.MethodGet, "/api/v1/projects/"+slug+"/pr-check?commit="+sha+suffix, key, nil)
			require.Equal(t, http.StatusOK, status, "%s", raw)
			var check struct {
				Conclusion string `json:"conclusion"`
			}
			require.NoError(t, json.Unmarshal(raw, &check))
			require.Equal(t, "failure", check.Conclusion, "branch %s, scope %s", branch, suffix)
		}
	}
}
