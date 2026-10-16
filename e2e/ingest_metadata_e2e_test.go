//go:build e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// contextRows counts the environment, target and artifact rows of a project.
func contextRows(t *testing.T, slug string) (environments, targets, artifacts int) {
	t.Helper()
	db := openE2EDB(t)
	for _, q := range []struct {
		table string
		into  *int
	}{{"environments", &environments}, {"targets", &targets}, {"artifacts", &artifacts}} {
		require.NoError(t, db.QueryRow(context.Background(),
			`SELECT count(*) FROM `+q.table+` WHERE project_id = (SELECT id FROM projects WHERE slug = $1)`, slug).Scan(q.into))
	}
	return environments, targets, artifacts
}

// Metadata that is too long or holds control characters is refused by name
// with 400, and a refused ingest leaves no environment, target or artifact
// row behind. Before, such a request created the rows and then failed.
func TestE2E_RefusedIngestMetadataLeavesNoContextRows(t *testing.T) {
	slug := newProject(t, "metadata")
	report := `{"ArtifactName":"a","Results":[{"Target":"t","Vulnerabilities":[{"VulnerabilityID":"CVE-1","PkgName":"p","Severity":"HIGH"}]}]}`

	for _, tc := range []struct {
		field string
		value any
	}{
		{"commit_sha", strings.Repeat("a", 1<<20)},
		{"commit_sha", "not a sha"},
		{"branch", "main\nforged line"},
		{"environment", strings.Repeat("e", 65)},
		{"artifact_name", strings.Repeat("n", 256)},
		{"owner", "own\x1ber"},
		{"changed_files", make([]string, 5001)},
	} {
		body := map[string]any{
			"project": slug, "scanner": "trivy", "raw_data": json.RawMessage(report),
			"environment": "meta-env", "artifact_name": "meta-artifact",
			tc.field: tc.value,
		}
		status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", adminToken, body)
		require.Equal(t, http.StatusBadRequest, status, "%s: %s", tc.field, raw)
		require.Contains(t, string(raw), "invalid_field")
		require.Contains(t, string(raw), tc.field)
	}

	environments, targets, artifacts := contextRows(t, slug)
	require.Zero(t, environments, "environment rows")
	require.Zero(t, targets, "target rows")
	require.Zero(t, artifacts, "artifact rows")
	require.Empty(t, listFindings(t, slug))
}

// A report the scanner format check refuses (422) is not recorded, and neither
// are the environment and artifact it named.
func TestE2E_UnprocessableIngestLeavesNoContextRows(t *testing.T) {
	slug := newProject(t, "metadata-422")

	status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", adminToken, map[string]any{
		"project": slug, "scanner": "trivy", "raw_data": json.RawMessage(`{"not":"trivy"}`),
		"environment": "ghost-env", "artifact_name": "ghost-artifact", "branch": "main",
	})
	require.Equal(t, http.StatusUnprocessableEntity, status, string(raw))

	environments, targets, artifacts := contextRows(t, slug)
	require.Zero(t, environments, "environment rows")
	require.Zero(t, targets, "target rows")
	require.Zero(t, artifacts, "artifact rows")
}
