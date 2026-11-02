//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_SeverityFilteredScanKeepsAReRatedFindingOpen pins that a report
// filtered by severity cannot close a finding by leaving it out. The finding
// was critical when last seen; the vendor may since have re-rated it to
// medium, which a HIGH,CRITICAL scan hides, and the server cannot tell that
// from a fix.
func TestE2E_SeverityFilteredScanKeepsAReRatedFindingOpen(t *testing.T) {
	slug := newProject(t, "filter-rerated")
	body := ingestBodyWith(t, slug, "trivy-alpine-scan.json", map[string]any{
		"scanner": "trivy", "branch": "main", "commit_sha": "f100000000000000000000000000000000000001",
	})
	var raw map[string]any
	require.NoError(t, json.Unmarshal(body["raw_data"].(json.RawMessage), &raw))
	result := raw["Results"].([]any)[0].(map[string]any)
	vulnerability := result["Vulnerabilities"].([]any)[1].(map[string]any)
	vulnerability["Severity"] = "CRITICAL"
	result["Vulnerabilities"] = []any{vulnerability}
	body["raw_data"] = raw
	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", adminToken, body, http.StatusCreated)
	require.Equal(t, "critical", listFindings(t, slug)[0].CurrentSeverity)

	result["Vulnerabilities"] = []any{}
	body["commit_sha"] = "f100000000000000000000000000000000000002"
	body["scan_filter"] = map[string]any{"severities": []string{"critical", "high"}}
	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", adminToken, body, http.StatusCreated)
	require.Equal(t, "open", listFindings(t, slug)[0].State,
		"a HIGH,CRITICAL scan that omits the finding may only have re-rated it below the filter")

	// A scan without a filter that omits it does close it.
	delete(body, "scan_filter")
	body["commit_sha"] = "f100000000000000000000000000000000000003"
	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", adminToken, body, http.StatusCreated)
	require.Equal(t, "fixed", listFindings(t, slug)[0].State)
}
