//go:build e2e

package e2e

import (
	"net/http"
	"os"
	"regexp"
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
	raw, err := os.ReadFile(absFixture(t, "checkov-terraform.json"))
	require.NoError(t, err)
	// Checkov's open-source output carries no rating; the fixture's come from the paid one.
	file := writeScanFile(t, regexp.MustCompile(`"severity":\s*"[A-Za-z]+"`).ReplaceAll(raw, []byte(`"severity": null`)))
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

// TestE2E_GateModes pins what each mode does to the adapter's exit code. The
// verdict is the same in all of them, and a failing gate needs the project to
// have asked for less.
func TestE2E_GateModes(t *testing.T) {
	const (
		mainCommit = "1111111111111111111111111111111111111111"
		prCommit   = "2222222222222222222222222222222222222222"
	)
	cases := []struct {
		mode        string
		mainExit    int
		changeExit  int
		wantMessage string
	}{
		{"enforce", 1, 1, "gate FAILED"},
		{"changes_only", 0, 1, "gate WOULD FAIL"},
		{"report_only", 0, 0, "gate WOULD FAIL"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			slug := newProject(t, "mode")
			key := mintKey(t, slug)
			env := []string{"API_URL=" + baseURL, "API_KEY=" + key}
			request[policyProvenance](t, http.MethodPut, "/api/v1/projects/"+slug+"/policy/overrides", adminToken,
				map[string]any{"overrides": map[string]string{"gate_mode": tc.mode}}, http.StatusOK)

			_, stderr, exit := runBin(t, adapterBin, env, "-project", slug, "-tool", "sarif",
				"-branch", "main", "-commit", mainCommit, "-file", absFixture(t, "high.sarif.json"))
			require.Equal(t, tc.mainExit, exit, stderr)
			require.Contains(t, stderr, tc.wantMessage)

			gs := request[struct {
				ThresholdBreached bool `json:"threshold_breached"`
				ReportOnly        bool `json:"report_only"`
			}](t, http.MethodGet, "/api/v1/projects/"+slug+"/gate", adminToken, nil, http.StatusOK)
			require.True(t, gs.ThresholdBreached, "every mode reports the same verdict")
			require.Equal(t, tc.mainExit == 0, gs.ReportOnly)

			_, stderr, exit = runBin(t, adapterBin, env, "-project", slug, "-tool", "sarif",
				"-branch", "feat/x", "-commit", prCommit, "-base-ref", "main",
				"-file", absFixture(t, "high-new.sarif.json"))
			require.Equal(t, tc.changeExit, exit, stderr)
		})
	}

	t.Run("changes_only still stops what a branch push introduces", func(t *testing.T) {
		slug := newProject(t, "mode-push")
		key := mintKey(t, slug)
		env := []string{"API_URL=" + baseURL, "API_KEY=" + key}
		request[projectDefaultBranch](t, http.MethodPut, "/api/v1/projects/"+slug, adminToken,
			map[string]any{"default_branch": "main"}, http.StatusOK)
		request[policyProvenance](t, http.MethodPut, "/api/v1/projects/"+slug+"/policy/overrides", adminToken,
			map[string]any{"overrides": map[string]string{"gate_mode": "changes_only"}}, http.StatusOK)

		_, stderr, exit := runBin(t, adapterBin, env, "-project", slug, "-tool", "sarif",
			"-branch", "main", "-commit", mainCommit, "-file", absFixture(t, "high.sarif.json"))
		require.Equal(t, 0, exit, "existing debt reports: %s", stderr)

		// No base named, as on a push build: the run is project-wide.
		_, stderr, exit = runBin(t, adapterBin, env, "-project", slug, "-tool", "sarif",
			"-branch", "feat/push", "-commit", prCommit, "-file", absFixture(t, "high-new.sarif.json"))
		require.Equal(t, 1, exit, "a new blocker fails the run: %s", stderr)

		_, stderr, exit = runBin(t, adapterBin, env, "-project", slug, "-tool", "sarif",
			"-branch", "feat/clean", "-commit", "3333333333333333333333333333333333333333",
			"-file", absFixture(t, "high.sarif.json"))
		require.Equal(t, 0, exit, "a branch that only carries existing debt passes: %s", stderr)
	})

	t.Run("an unknown mode is refused", func(t *testing.T) {
		slug := newProject(t, "mode-unknown")
		status, _ := doJSON(t, http.MethodPut, "/api/v1/projects/"+slug+"/policy/overrides", adminToken,
			map[string]any{"overrides": map[string]string{"gate_mode": "off"}})
		require.Equal(t, http.StatusBadRequest, status)
	})
}
