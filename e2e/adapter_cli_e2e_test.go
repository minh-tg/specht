//go:build e2e

package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// absFixture resolves a testdata fixture to an absolute path so the adapter
// binary (whose cwd is the repo root) can open it.
func absFixture(t *testing.T, name string) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("testdata", name))
	require.NoError(t, err)
	_, err = os.Stat(abs)
	require.NoError(t, err)
	return abs
}

// TestE2E_AdapterGateVerdicts exercises the CI binary exactly as a pipeline
// would: ingest via API key, read the gate with the same key, and exit with
// the documented contract — 0 pass, 1 gate failed, 2 configuration/API error.
func TestE2E_AdapterGateVerdicts(t *testing.T) {
	t.Run("blocking finding fails the build", func(t *testing.T) {
		slug := newProject(t, "adapter-block")
		key := mintKey(t, slug)
		_, stderr, exit := runBin(t, adapterBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"-project", slug, "-tool", "sarif", "-file", absFixture(t, "high.sarif.json"))
		require.Equal(t, 1, exit, "adapter must exit 1 on a breached gate; stderr:\n%s", stderr)
		require.Contains(t, stderr, "gate FAILED: 1 blocking finding(s)")
		require.Contains(t, stderr, "1 finding(s)")
	})

	t.Run("clean report passes the build", func(t *testing.T) {
		slug := newProject(t, "adapter-pass")
		key := mintKey(t, slug)
		_, stderr, exit := runBin(t, adapterBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"-project", slug, "-tool", "sarif", "-file", absFixture(t, "medium.sarif.json"))
		require.Equal(t, 0, exit, "adapter must exit 0 when the gate passes; stderr:\n%s", stderr)
		require.Contains(t, stderr, "gate PASSED: no blocking findings")
	})

	t.Run("excluded scanner short-circuits without ingesting", func(t *testing.T) {
		slug := newProject(t, "adapter-skip")
		key := mintKey(t, slug)
		_, stderr, exit := runBin(t, adapterBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"-project", slug, "-tool", "sarif", "-exclude-tool", "sarif",
			"-file", absFixture(t, "high.sarif.json"))
		require.Equal(t, 0, exit, "excluded scans are a skip, not a failure; stderr:\n%s", stderr)
		require.Contains(t, stderr, `skipped: scanner "sarif" excluded`)

		findings := listFindings(t, slug)
		require.Empty(t, findings, "an excluded scan must not ingest anything")
	})

	t.Run("missing API key is a configuration error", func(t *testing.T) {
		_, stderr, exit := runBin(t, adapterBin, nil,
			"-project", "anything", "-tool", "sarif",
			"-file", absFixture(t, "high.sarif.json"))
		require.Equal(t, 2, exit)
		require.Contains(t, stderr, "API_KEY environment variable is required")
	})
}

// TestE2E_CLIGateAndFindingsContract exercises the specht CLI against the
// live server with a project API key: exit 1 on breached gate (JSON and
// human output), exit 0 when clean, and findings listing.
func TestE2E_CLIGateAndFindingsContract(t *testing.T) {
	blockedSlug := newProject(t, "cli-block")
	blockedKey := mintKey(t, blockedSlug)
	ingestFixture(t, blockedSlug, blockedKey, "high.sarif.json")

	cleanSlug := newProject(t, "cli-pass")
	cleanKey := mintKey(t, cleanSlug)
	ingestFixture(t, cleanSlug, cleanKey, "medium.sarif.json")

	t.Run("gate check exits 1 with JSON verdict on a breached project", func(t *testing.T) {
		stdout, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + blockedKey},
			"gate", "check", "--project", blockedSlug, "--format", "json")
		require.Equal(t, 1, exit, "breached gate must exit 1; stderr:\n%s", stderr)

		var gs gateStatus
		require.NoError(t, json.Unmarshal([]byte(stdout), &gs), "stdout: %s", stdout)
		require.True(t, gs.ThresholdBreached)
		require.EqualValues(t, 1, gs.BlockingCount)
		require.NotEmpty(t, gs.BlockedBy)
	})

	t.Run("gate check exits 0 with a passing verdict", func(t *testing.T) {
		stdout, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + cleanKey},
			"gate", "check", "--project", cleanSlug)
		require.Equal(t, 0, exit, "clean gate must exit 0; stderr:\n%s", stderr)
		require.Contains(t, stdout, "gate PASSED: no blocking findings")
	})

	t.Run("findings list reports the blocking finding", func(t *testing.T) {
		stdout, stderr, exit := runBin(t, cliBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + blockedKey},
			"findings", "list", "--project", blockedSlug)
		require.Equal(t, 0, exit, "stderr:\n%s", stderr)
		require.Contains(t, stdout, "Hardcoded credentials in app config")
		require.Contains(t, stdout, "high")
	})

	t.Run("missing API key is a configuration error", func(t *testing.T) {
		_, stderr, exit := runBin(t, cliBin, nil,
			"gate", "check", "--project", blockedSlug)
		require.Equal(t, 2, exit)
		require.Contains(t, stderr, "API_KEY environment variable is required")
	})
}
