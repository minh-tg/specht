//go:build e2e

package e2e

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// cli runs the specht binary as a person would, signed in as the admin.
func cli(t *testing.T, args ...string) (stdout, stderr string, exit int) {
	t.Helper()
	return runBin(t, cliBin, []string{"API_URL=" + baseURL, "API_KEY=" + adminToken}, args...)
}

// TestE2E_CLITriagesAFindingAndReadsItsHistory walks a person who blocks a build with one
// finding, then decides it from the terminal.
func TestE2E_CLITriagesAFindingAndReadsItsHistory(t *testing.T) {
	slug := newProject(t, "cli-triage")
	ingestFixture(t, slug, mintKey(t, slug), "high.sarif.json")
	finding := listFindings(t, slug)[0].ID
	require.True(t, getGate(t, slug, "").ThresholdBreached, "the high finding blocks before any decision")

	stdout, stderr, exit := cli(t, "findings", "triage", finding, "--state", "in_triage")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "in_triage")

	_, stderr, exit = cli(t, "findings", "triage", finding, "--state", "false_positive")
	require.Equal(t, 2, exit, "a decision that ignores the gate needs a reason")
	require.Contains(t, stderr, "reason")

	stdout, stderr, exit = cli(t, "findings", "triage", finding, "--state", "false_positive", "--reason", "test fixture")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "gate: ignore")
	require.False(t, getGate(t, slug, "").ThresholdBreached, "the decision lifted the block")

	stdout, stderr, exit = cli(t, "findings", "events", finding)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "false_positive", "the history shows the decision")
	require.Contains(t, stdout, "test fixture")

	stdout, stderr, exit = cli(t, "--format", "json", "findings", "triage", finding, "--state", "exploitable")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, `"analysis_state": "exploitable"`)
}

// TestE2E_CLIBulkTriage decides several findings at once.
func TestE2E_CLIBulkTriage(t *testing.T) {
	slug := newProject(t, "cli-bulk")
	ingestFixture(t, slug, mintKey(t, slug), "high-medium.sarif.json")
	findings := listFindings(t, slug)
	require.Len(t, findings, 2)

	stdout, stderr, exit := cli(t, "findings", "bulk-triage", "--id", findings[0].ID+","+findings[1].ID,
		"--state", "not_affected", "--reason", "dev only")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, findings[0].ID)
	require.Contains(t, stdout, findings[1].ID)
	require.False(t, getGate(t, slug, "").ThresholdBreached)
}

func firstJSONField(t *testing.T, document, field string) string {
	t.Helper()
	var rows []map[string]any
	require.NoError(t, json.Unmarshal([]byte(document), &rows))
	require.NotEmpty(t, rows)
	value, _ := rows[0][field].(string)
	require.NotEmpty(t, value, field)
	return value
}

// TestE2E_CLIWaiverLifecycle walks a waiver from request to deletion without the web page.
func TestE2E_CLIWaiverLifecycle(t *testing.T) {
	slug := newProject(t, "cli-waivers")
	ingestFixture(t, slug, mintKey(t, slug), "high.sarif.json")
	finding := listFindings(t, slug)[0].ID
	require.True(t, getGate(t, slug, "").ThresholdBreached)
	soon := time.Now().AddDate(0, 0, 30).Format("2006-01-02")

	var waiverID string
	t.Run("a request waits for approval and blocks until then", func(t *testing.T) {
		stdout, stderr, exit := cli(t, "waivers", "request", "--project", slug, "--finding", finding,
			"--reason", "vendor fix is due", "--expires", soon)
		require.Zero(t, exit, stderr)
		require.Contains(t, stdout, "pending")
		require.True(t, getGate(t, slug, "").ThresholdBreached, "a request does not lift the block")

		stdout, stderr, exit = cli(t, "--format", "json", "waivers", "list", "--project", slug)
		require.Zero(t, exit, stderr)
		waiverID = firstJSONField(t, stdout, "id")
	})

	t.Run("approving it lifts the block", func(t *testing.T) {
		stdout, stderr, exit := cli(t, "waivers", "approve", "--project", slug, "--id", waiverID, "--note", "agreed")
		require.Zero(t, exit, stderr)
		require.Contains(t, stdout, "approved")
		require.False(t, getGate(t, slug, "").ThresholdBreached)
	})

	t.Run("turning it off blocks again, and its history says what happened", func(t *testing.T) {
		_, stderr, exit := cli(t, "waivers", "toggle", "--project", slug, "--id", waiverID)
		require.Zero(t, exit, stderr)
		require.True(t, getGate(t, slug, "").ThresholdBreached)

		stdout, stderr, exit := cli(t, "waivers", "events", "--project", slug, "--id", waiverID)
		require.Zero(t, exit, stderr)
		require.Contains(t, stdout, "approved")
	})

	t.Run("a deleted waiver is gone", func(t *testing.T) {
		stdout, stderr, exit := cli(t, "waivers", "delete", "--project", slug, "--id", waiverID)
		require.Zero(t, exit, stderr)
		require.Contains(t, stdout, "deleted")

		stdout, stderr, exit = cli(t, "waivers", "list", "--project", slug)
		require.Zero(t, exit, stderr)
		require.Contains(t, stdout, "No waivers.")
	})
}

func TestE2E_CLIWaiverCreateCoversTheNamedFinding(t *testing.T) {
	slug := newProject(t, "cli-waiver-create")
	ingestFixture(t, slug, mintKey(t, slug), "high.sarif.json")
	finding := listFindings(t, slug)[0].ID

	stdout, stderr, exit := cli(t, "waivers", "create", "--project", slug, "--name", "Accepted for now",
		"--description", "fixture", "--finding", finding, "--expires", "2099-01-01")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "approved")
	require.False(t, getGate(t, slug, "").ThresholdBreached, "the waiver lifts the block")

	_, stderr, exit = cli(t, "waivers", "create", "--project", slug, "--name", "Nothing covered")
	require.Equal(t, 2, exit, "a waiver that covers nothing is refused")
	require.NotEmpty(t, stderr)
}
