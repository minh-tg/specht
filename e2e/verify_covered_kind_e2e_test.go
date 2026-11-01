//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// trivyDocBody is an ingest body for a hand-written Trivy document.
func trivyDocBody(slug, branch, commit string, doc map[string]any) map[string]any {
	raw, _ := json.Marshal(doc)
	return map[string]any{
		"project": slug, "scanner": "trivy", "branch": branch, "commit_sha": commit,
		"raw_data": json.RawMessage(raw),
	}
}

// A Trivy report that covered no sca class cannot show an sca finding is
// gone. Auto-close refuses it, and so must the manual verify.
func TestE2E_VerifyFixNeedsTheReportToHaveCoveredTheFindingKind(t *testing.T) {
	cases := map[string][]any{
		"no result class at all": {},
		"only a config class":    {map[string]any{"Target": "Dockerfile", "Class": "config", "Type": "dockerfile"}},
	}
	for name, results := range cases {
		t.Run(name, func(t *testing.T) {
			slug := newProject(t, "verify-kind")
			ingestRaw(t, slug, "trivy", "trivy-alpine-scan.json",
				map[string]any{"branch": "main", "commit_sha": "d000000000000000000000000000000000000001"})
			before := listScanFindings(t, slug)
			require.Len(t, before, 2)
			for _, f := range before {
				require.Equal(t, "open", f.State)
				require.Equal(t, "sca", f.FindingKind)
			}

			request[ingestResponse](t, http.MethodPost, "/api/v1/reports", adminToken,
				trivyDocBody(slug, "main", "d000000000000000000000000000000000000002", map[string]any{
					"SchemaVersion": 2, "ArtifactName": "alpine:3.20", "ArtifactType": "container_image",
					"Results": results,
				}), http.StatusCreated)
			for _, f := range listScanFindings(t, slug) {
				require.Equal(t, "open", f.State, "auto-close refuses: the report covered no sca class")
			}

			got := request[verifyResponse](t, http.MethodPost,
				"/api/v1/findings/"+before[0].ID+"/verify", adminToken, nil, http.StatusOK)
			require.Equal(t, "inconclusive", got.Outcome, "detail=%q", got.Detail)
			require.Contains(t, got.Detail, "does not cover this kind of finding")
			for _, f := range listScanFindings(t, slug) {
				require.Equal(t, "open", f.State)
			}
		})
	}
}

// A Trivy document that lists no result class vouches for no finding kind, so
// the report does not claim to be a complete scan.
func TestE2E_TrivyReportWithNoResultClassIsNotComplete(t *testing.T) {
	slug := newProject(t, "trivy-no-class")
	res := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", adminToken,
		trivyDocBody(slug, "main", "9000000000000000000000000000000000000001", map[string]any{
			"SchemaVersion": 2, "ArtifactName": "alpine:3.20", "ArtifactType": "container_image",
			"Results": []any{},
		}), http.StatusCreated)
	var report struct {
		ScanCompleteness string `json:"scan_completeness"`
	}
	status, raw := doJSON(t, http.MethodGet, "/api/v1/reports/"+res.ReportID, adminToken, nil)
	require.Equal(t, http.StatusOK, status, "%s", raw)
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Equal(t, "unknown", report.ScanCompleteness)

	full := ingestRaw(t, slug, "trivy", "trivy-alpine-scan.json",
		map[string]any{"branch": "main", "commit_sha": "9000000000000000000000000000000000000002"})
	status, raw = doJSON(t, http.MethodGet, "/api/v1/reports/"+full.ReportID, adminToken, nil)
	require.Equal(t, http.StatusOK, status, "%s", raw)
	require.NoError(t, json.Unmarshal(raw, &report))
	require.Equal(t, "complete", report.ScanCompleteness)
}
