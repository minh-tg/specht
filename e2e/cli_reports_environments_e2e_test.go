//go:build e2e

package e2e

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_CLIUploadsAndManagesReports walks a person who uploads a scanner's file from the
// terminal, sees it in the history, and removes it.
func TestE2E_CLIUploadsAndManagesReports(t *testing.T) {
	slug := newProject(t, "cli-reports")
	file := absFixture(t, "high.sarif.json")

	stdout, stderr, exit := cli(t, "reports", "upload", "--project", slug, "--scanner", "sarif", "--file", file, "--commit", baseSHA)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "1 finding, gate blocked")

	stdout, stderr, exit = cli(t, "reports", "upload", "--project", slug, "--scanner", "sarif", "--file", file, "--commit", baseSHA)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "already ingested", "the same bytes at the same commit are a replay")

	_, stderr, exit = cli(t, "reports", "upload", "--project", slug, "--scanner", "trivy", "--file", file)
	require.Equal(t, 2, exit, "a file under the wrong scanner is refused")
	require.Contains(t, stderr, "choose sarif as the scanner", "and the message says what to pick")

	stdout, stderr, exit = cli(t, "--format", "json", "reports", "list", "--project", slug)
	require.Zero(t, exit, stderr)
	reportID := firstJSONField(t, stdout, "id")

	stdout, stderr, exit = cli(t, "reports", "get", "--id", reportID)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "sarif")

	stdout, stderr, exit = cli(t, "reports", "delete", "--project", slug, "--id", reportID)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "1 finding archived")

	stdout, stderr, exit = cli(t, "reports", "list", "--project", slug)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "No reports.")
}

func TestE2E_CLIUploadsLineBasedOutput(t *testing.T) {
	slug := newProject(t, "cli-jsonl")
	stdout, stderr, exit := cli(t, "reports", "upload", "--project", slug, "--scanner", "nuclei", "--file", absFixture(t, "nuclei.jsonl"))
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "report ")
}

// TestE2E_CLIClassifiesAnEnvironment sets an environment's exposure from the terminal and checks
// that a later scan keeps it.
func TestE2E_CLIClassifiesAnEnvironment(t *testing.T) {
	slug := newProject(t, "cli-environments")
	_, stderr, exit := cli(t, "reports", "upload", "--project", slug, "--scanner", "sarif",
		"--file", absFixture(t, "high.sarif.json"), "--environment", "production", "--commit", baseSHA)
	require.Zero(t, exit, stderr)

	stdout, stderr, exit := cli(t, "environments", "list", "--project", slug)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "production")
	require.Contains(t, stdout, "internal", "a scan creates it as not internet facing")

	stdout, stderr, exit = cli(t, "environments", "set", "--project", slug, "--env", "production",
		"--internet-facing", "--data-sensitivity", "restricted")
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "internet facing")
	require.Contains(t, stdout, "restricted")

	_, stderr, exit = cli(t, "reports", "upload", "--project", slug, "--scanner", "sarif",
		"--file", absFixture(t, "medium.sarif.json"), "--environment", "production", "--commit", deadSHA)
	require.Zero(t, exit, stderr)

	stdout, stderr, exit = cli(t, "environments", "list", "--project", slug)
	require.Zero(t, exit, stderr)
	require.Contains(t, stdout, "restricted", "a later scan leaves the settings alone")
	require.Contains(t, stdout, "internet facing")

	_, stderr, exit = cli(t, "environments", "set", "--project", slug, "--env", "production", "--tier", "prod")
	require.Equal(t, 2, exit, "a tier outside the vocabulary is refused")
	require.NotEmpty(t, stderr)

	_, stderr, exit = cli(t, "environments", "set", "--project", slug, "--env", "nowhere", "--tier", "test")
	require.Equal(t, 2, exit)
	require.Contains(t, stderr, "nowhere")
}

func TestE2E_CLIListsScannersTargetsAndArtifacts(t *testing.T) {
	stdout, stderr, exit := cli(t, "scanners", "list")
	require.Zero(t, exit, stderr)
	for _, want := range []string{"trivy", "Trivy", "semgrep scan --sarif", "(.json, .sarif)", "nuclei -u"} {
		require.Contains(t, stdout, want)
	}

	slug := newProject(t, "cli-inventory")
	_, stderr, exit = cli(t, "reports", "upload", "--project", slug, "--scanner", "sarif", "--file", absFixture(t, "high.sarif.json"))
	require.Zero(t, exit, stderr)
	for _, noun := range []string{"targets", "artifacts"} {
		_, stderr, exit = cli(t, noun, "list", "--project", slug)
		require.Zero(t, exit, "%s: %s", noun, stderr)
	}
}
