//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_UnratedFindingsAreNeverSilent pins the Checkov-only project: its
// open-source output rates nothing, so the gate cannot judge it. The verdict says
// so, and a project can make those findings block.
func TestE2E_UnratedFindingsAreNeverSilent(t *testing.T) {
	slug := newProject(t, "unrated")
	key := mintKey(t, slug)
	env := []string{"API_URL=" + baseURL, "API_KEY=" + key}
	file := absFixture(t, "checkov-terraform.json")
	send := func(commit string) (string, int) {
		_, stderr, exit := runBin(t, adapterBin, env, "-project", slug, "-tool", "checkov",
			"-branch", "main", "-commit", commit, "-file", file)
		return stderr, exit
	}

	stderr, exit := send("1111111111111111111111111111111111111111")
	require.Equal(t, 0, exit, stderr)
	require.Contains(t, stderr, "have no severity, so the gate did not judge them")

	type status struct {
		ThresholdBreached bool  `json:"threshold_breached"`
		BlockingCount     int64 `json:"blocking_count"`
		UnratedCount      int   `json:"unrated_count"`
	}
	passing := request[status](t, http.MethodGet, "/api/v1/projects/"+slug+"/gate", adminToken, nil, http.StatusOK)
	require.False(t, passing.ThresholdBreached)
	require.Positive(t, passing.UnratedCount)

	request[policyProvenance](t, http.MethodPut, "/api/v1/projects/"+slug+"/policy/overrides", adminToken,
		map[string]any{"overrides": map[string]string{"unrated_gate": "block"}}, http.StatusOK)

	blocked := request[status](t, http.MethodGet, "/api/v1/projects/"+slug+"/gate", adminToken, nil, http.StatusOK)
	require.True(t, blocked.ThresholdBreached)
	require.EqualValues(t, passing.UnratedCount, blocked.BlockingCount)
	require.Zero(t, blocked.UnratedCount, "they are judged now, so there is nothing left to warn about")

	stderr, exit = send("1111111111111111111111111111111111111112")
	require.Equal(t, 1, exit, stderr)
	require.NotContains(t, stderr, "have no severity")
}
