//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeScanFile puts one scanner output in a temp file for the adapter.
func writeScanFile(t *testing.T, content []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scan")
	require.NoError(t, os.WriteFile(path, content, 0o600))
	return path
}

// withoutResults returns a scanner's real output with its findings removed, so
// the clean scan is the same scanner run with nothing left to report.
func withoutResults(t *testing.T, path string, empty func(map[string]any)) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	var doc map[string]any
	require.NoError(t, json.Unmarshal(raw, &doc))
	empty(doc)
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

func openFindingCount(t *testing.T, slug string) int {
	t.Helper()
	open := 0
	for _, f := range listFindings(t, slug) {
		if f.State == "open" || f.State == "reopened" {
			open++
		}
	}
	return open
}

// TestE2E_CleanScanClosesFindings runs each scanner that cannot show what it
// looked at through the real adapter: the report with findings, then the same
// scanner with nothing to report, on the same branch.
func TestE2E_CleanScanClosesFindings(t *testing.T) {
	const parsers = "../internal/parser/"
	cases := []struct {
		tool  string
		dirty string
		clean func(t *testing.T, dirty string) []byte
	}{
		{"semgrep", parsers + "semgrep/testdata/semgrep-sarif.json", func(t *testing.T, dirty string) []byte {
			return withoutResults(t, dirty, func(doc map[string]any) {
				for _, run := range doc["runs"].([]any) {
					run.(map[string]any)["results"] = []any{}
				}
			})
		}},
		{"semgrep", parsers + "semgrep/testdata/semgrep-native.json", func(t *testing.T, dirty string) []byte {
			return withoutResults(t, dirty, func(doc map[string]any) { doc["results"] = []any{} })
		}},
		{"gitleaks", "testdata/gitleaks.json", func(*testing.T, string) []byte { return []byte("[]") }},
		{"tfsec", parsers + "tfsec/testdata/tfsec.json", func(t *testing.T, dirty string) []byte {
			return withoutResults(t, dirty, func(doc map[string]any) { doc["results"] = []any{} })
		}},
		{"osv-scanner", parsers + "osvscanner/testdata/go-scan.json", func(t *testing.T, dirty string) []byte {
			return withoutResults(t, dirty, func(doc map[string]any) { doc["results"] = []any{} })
		}},
		{"dependency-check", "testdata/dependency-check.json", func(t *testing.T, dirty string) []byte {
			return withoutResults(t, dirty, func(doc map[string]any) { doc["dependencies"] = []any{} })
		}},
		{"sbom", parsers + "sbom/testdata/grype-cyclonedx.json", func(t *testing.T, dirty string) []byte {
			return withoutResults(t, dirty, func(doc map[string]any) { doc["vulnerabilities"] = []any{} })
		}},
		{"nuclei", parsers + "nuclei/testdata/nuclei.jsonl", func(*testing.T, string) []byte { return nil }},
	}
	for i, tc := range cases {
		t.Run(tc.tool+"/"+strconv.Itoa(i), func(t *testing.T) {
			slug := newProject(t, "clean-"+tc.tool)
			key := mintKey(t, slug)
			env := []string{"API_URL=" + baseURL, "API_KEY=" + key}
			send := func(file, commit string) (string, int) {
				_, stderr, exit := runBin(t, adapterBin, env, "-project", slug, "-tool", tc.tool,
					"-branch", "main", "-commit", commit, "-file", file)
				return stderr, exit
			}

			dirty, err := filepath.Abs(tc.dirty)
			require.NoError(t, err)
			stderr, exit := send(dirty, "1111111111111111111111111111111111111111")
			require.Less(t, exit, 2, stderr)
			require.Positive(t, openFindingCount(t, slug), "the first scan must report findings: %s", stderr)

			stderr, exit = send(writeScanFile(t, tc.clean(t, dirty)), "1111111111111111111111111111111111111112")
			require.Equal(t, 0, exit, "a clean scan must pass the gate: %s", stderr)
			require.Zero(t, openFindingCount(t, slug), "a clean scan must close what it no longer reports")
		})
	}
}

// TestE2E_CleanScanLeavesFindingsOpen pins the three ways a scan does not close.
func TestE2E_CleanScanLeavesFindingsOpen(t *testing.T) {
	semgrep, err := filepath.Abs("../internal/parser/semgrep/testdata/semgrep-sarif.json")
	require.NoError(t, err)
	clean := withoutResults(t, semgrep, func(doc map[string]any) {
		for _, run := range doc["runs"].([]any) {
			run.(map[string]any)["results"] = []any{}
		}
	})
	scan := func(t *testing.T, slug, key, file, commit string, extra ...string) {
		t.Helper()
		args := append([]string{
			"-project", slug, "-tool", "semgrep", "-branch", "main", "-commit", commit, "-file", file,
		}, extra...)
		_, stderr, exit := runBin(t, adapterBin, []string{"API_URL=" + baseURL, "API_KEY=" + key}, args...)
		require.Less(t, exit, 2, stderr)
	}

	t.Run("a project that keeps the scanner manual", func(t *testing.T) {
		slug := newProject(t, "clean-manual")
		key := mintKey(t, slug)
		request[policyProvenance](t, http.MethodPut, "/api/v1/projects/"+slug+"/policy/overrides", adminToken,
			map[string]any{"overrides": map[string]string{"manual_close_scanners": "semgrep"}}, http.StatusOK)
		scan(t, slug, key, semgrep, "1111111111111111111111111111111111111111")
		before := openFindingCount(t, slug)
		require.Positive(t, before)
		scan(t, slug, key, writeScanFile(t, clean), "1111111111111111111111111111111111111112")
		require.Equal(t, before, openFindingCount(t, slug))
	})

	t.Run("a scan declared incremental", func(t *testing.T) {
		slug := newProject(t, "clean-incremental")
		key := mintKey(t, slug)
		scan(t, slug, key, semgrep, "1111111111111111111111111111111111111111")
		before := openFindingCount(t, slug)
		require.Positive(t, before)
		scan(t, slug, key, writeScanFile(t, clean), "1111111111111111111111111111111111111112",
			"-scan-mode", "incremental", "-base-ref", "1111111111111111111111111111111111111111")
		require.Equal(t, before, openFindingCount(t, slug))
	})

	t.Run("a clean scan on another branch", func(t *testing.T) {
		slug := newProject(t, "clean-other-branch")
		key := mintKey(t, slug)
		scan(t, slug, key, semgrep, "1111111111111111111111111111111111111111")
		before := openFindingCount(t, slug)
		require.Positive(t, before)
		_, stderr, exit := runBin(t, adapterBin, []string{"API_URL=" + baseURL, "API_KEY=" + key},
			"-project", slug, "-tool", "semgrep", "-branch", "feat/x",
			"-commit", "1111111111111111111111111111111111111113", "-file", writeScanFile(t, clean))
		require.Less(t, exit, 2, stderr)
		require.Equal(t, before, openFindingCount(t, slug))
	})

	t.Run("an unknown scanner name is refused", func(t *testing.T) {
		slug := newProject(t, "clean-unknown")
		status, _ := doJSON(t, http.MethodPut, "/api/v1/projects/"+slug+"/policy/overrides", adminToken,
			map[string]any{"overrides": map[string]string{"manual_close_scanners": "no-such-scanner"}})
		require.Equal(t, http.StatusBadRequest, status)
	})
}

// TestE2E_FixedOnBranchLeavesNoBlockerOnMain is the pull request that fails, is
// fixed, and must leave nothing behind, for a scanner that cannot show its
// coverage.
func TestE2E_FixedOnBranchLeavesNoBlockerOnMain(t *testing.T) {
	semgrep, err := filepath.Abs("../internal/parser/semgrep/testdata/semgrep-sarif.json")
	require.NoError(t, err)
	clean := writeScanFile(t, withoutResults(t, semgrep, func(doc map[string]any) {
		for _, run := range doc["runs"].([]any) {
			run.(map[string]any)["results"] = []any{}
		}
	}))
	slug := newProject(t, "clean-pr")
	key := mintKey(t, slug)
	env := []string{"API_URL=" + baseURL, "API_KEY=" + key}
	push := func(file, branch, commit string, extra ...string) int {
		args := append([]string{
			"-project", slug, "-tool", "semgrep", "-branch", branch, "-commit", commit, "-file", file,
		}, extra...)
		_, stderr, exit := runBin(t, adapterBin, env, args...)
		require.Less(t, exit, 2, stderr)
		return exit
	}

	require.Equal(t, 0, push(clean, "main", "1111111111111111111111111111111111111111"))
	push(semgrep, "feat/x", "2222222222222222222222222222222222222222", "-base-ref", "main")
	require.Positive(t, openFindingCount(t, slug))
	require.Equal(t, 0, push(clean, "feat/x", "2222222222222222222222222222222222222223", "-base-ref", "main"),
		"the fixed pull request must pass")
	require.Zero(t, openFindingCount(t, slug), "the fix must close what the branch introduced")
	require.Equal(t, 0, push(clean, "main", "1111111111111111111111111111111111111112"), "main must stay clean")
}

// TestE2E_ArtifactSeparatesJobsOfOneScanner pins the matrix pipeline: one job per
// lockfile, where a clean scan of one must not close the other's findings.
func TestE2E_ArtifactSeparatesJobsOfOneScanner(t *testing.T) {
	dirty, err := filepath.Abs("../internal/parser/osvscanner/testdata/go-scan.json")
	require.NoError(t, err)
	clean := writeScanFile(t, []byte(`{"results":[]}`))
	slug := newProject(t, "clean-matrix")
	key := mintKey(t, slug)
	scan := func(file, artifact, commit string) {
		t.Helper()
		_, stderr, exit := runBin(t, adapterBin, []string{"API_URL=" + baseURL, "API_KEY=" + key},
			"-project", slug, "-tool", "osv-scanner", "-branch", "main", "-artifact", artifact,
			"-commit", commit, "-file", file)
		require.Less(t, exit, 2, stderr)
	}
	scan(dirty, "services/a", "1111111111111111111111111111111111111111")
	before := openFindingCount(t, slug)
	require.Positive(t, before)

	scan(clean, "services/b", "1111111111111111111111111111111111111112")
	require.Equal(t, before, openFindingCount(t, slug), "another job's clean scan closes nothing")

	scan(clean, "services/a", "1111111111111111111111111111111111111113")
	require.Zero(t, openFindingCount(t, slug), "the same job's clean scan closes them")
}
