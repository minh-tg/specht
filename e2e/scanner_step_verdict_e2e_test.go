//go:build e2e

package e2e

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_ScannerStepCountsOnlyItsOwnFindings pins the exit code of one
// scanner's CI step to that scanner: a clean Semgrep step passes while Trivy
// findings block the project, and its log names the project total. The
// project verdict without a scanner keeps counting every scanner.
func TestE2E_ScannerStepCountsOnlyItsOwnFindings(t *testing.T) {
	slug := newProject(t, "scanner-step")
	key := mintKey(t, slug)
	env := []string{"API_URL=" + baseURL, "API_KEY=" + key}
	step := func(tool, file, commit string) (string, int) {
		t.Helper()
		_, stderr, exit := runBin(t, adapterBin, env, "-project", slug, "-tool", tool,
			"-branch", "main", "-commit", commit, "-file", file)
		return stderr, exit
	}

	stderr, exit := step("trivy", absFixture(t, "trivy-alpine-scan.json"), "1111111111111111111111111111111111111111")
	require.Equal(t, 1, exit, "the Trivy step fails on its own findings: %s", stderr)

	project := getGate(t, slug, "")
	require.True(t, project.ThresholdBreached)
	require.Positive(t, project.BlockingCount)
	require.Equal(t, project.BlockingCount, getGate(t, slug, "scanner=trivy").BlockingCount,
		"every blocker came from Trivy")
	require.Zero(t, getGate(t, slug, "scanner=semgrep").BlockingCount)

	semgrep, err := filepath.Abs("../internal/parser/semgrep/testdata/semgrep-sarif.json")
	require.NoError(t, err)
	clean := writeScanFile(t, withoutResults(t, semgrep, func(doc map[string]any) {
		for _, run := range doc["runs"].([]any) {
			run.(map[string]any)["results"] = []any{}
		}
	}))
	stderr, exit = step("semgrep", clean, "1111111111111111111111111111111111111111")
	require.Equal(t, 0, exit, "a clean Semgrep step passes while Trivy findings block: %s", stderr)
	require.Contains(t, stderr, "gate PASSED: no blocking findings from semgrep")
	require.Contains(t, stderr, fmt.Sprintf("project gate: %d blocking across all scanners", project.BlockingCount))

	require.Equal(t, project.BlockingCount, getGate(t, slug, "").BlockingCount,
		"the project verdict still counts every scanner")
}
