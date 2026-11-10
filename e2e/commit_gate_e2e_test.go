//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_CommitGateJoinsScanners pins the change view's verdict source: two
// scanners report on one commit, each report's own gate names only its own
// blockers, and the commit gate names both, whichever report a reader came
// from.
func TestE2E_CommitGateJoinsScanners(t *testing.T) {
	slug := newProject(t, "commit-gate")
	key := mintKey(t, slug)
	const commit = "4444444444444444444444444444444444444444"
	change := map[string]any{
		"commit_sha":    commit,
		"base_revision": baseSHA,
		"branch":        "feat/two-scanners",
	}

	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high-medium.sarif.json", map[string]any{"commit_sha": baseSHA}),
		http.StatusCreated)
	sast := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high-new.sarif.json", change), http.StatusCreated)
	leaks := ingestRaw(t, slug, "gitleaks", "gitleaks.json", change)

	sastGate := getGate(t, slug, "introduced_only=true&report_id="+sast.ReportID)
	leaksGate := getGate(t, slug, "introduced_only=true&report_id="+leaks.ReportID)
	require.NotEmpty(t, sastGate.BlockedBy, "the SARIF report must introduce a blocker")
	require.NotEmpty(t, leaksGate.BlockedBy, "the Gitleaks report must introduce a blocker")
	for _, id := range leaksGate.BlockedBy {
		require.NotContains(t, sastGate.BlockedBy, id, "one report's gate must not name the other's blockers")
	}

	want := append(append([]string{}, sastGate.BlockedBy...), leaksGate.BlockedBy...)
	for name, sha := range map[string]string{"lower case": commit, "upper case": strings.ToUpper(commit)} {
		t.Run(name, func(t *testing.T) {
			gate := getGate(t, slug, "introduced_only=true&commit="+sha)
			require.True(t, gate.ThresholdBreached)
			require.ElementsMatch(t, want, gate.BlockedBy)
			require.EqualValues(t, len(want), gate.BlockingCount)
		})
	}

	t.Run("a commit nobody scanned has no verdict", func(t *testing.T) {
		status, body := doJSON(t, http.MethodGet,
			"/api/v1/projects/"+slug+"/gate?introduced_only=true&commit=5555555555555555555555555555555555555555",
			adminToken, nil)
		require.Equal(t, http.StatusNotFound, status, "%s", body)
		require.Contains(t, string(body), "no_report_for_commit")
	})

	t.Run("a prefix matches nothing", func(t *testing.T) {
		status, _ := doJSON(t, http.MethodGet,
			"/api/v1/projects/"+slug+"/gate?introduced_only=true&commit="+commit[:7], adminToken, nil)
		require.Equal(t, http.StatusNotFound, status)
	})

	t.Run("report and commit together are refused", func(t *testing.T) {
		status, body := doJSON(t, http.MethodGet,
			"/api/v1/projects/"+slug+"/gate?introduced_only=true&commit="+commit+"&report_id="+sast.ReportID,
			adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Contains(t, string(body), "conflicting_scope")
	})
}
