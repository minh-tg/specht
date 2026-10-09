//go:build e2e

package e2e

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"
)

// adapterReportID matches the adapter's "report <id> ingested" diagnostic.
var adapterReportID = regexp.MustCompile(`report ([0-9a-fA-F-]{36}) ingested`)

// reportIDFromAdapter extracts the report id the adapter named on stderr.
func reportIDFromAdapter(t *testing.T, stderr string) string {
	t.Helper()
	m := adapterReportID.FindStringSubmatch(stderr)
	require.Len(t, m, 2, "adapter output must name the report; stderr:\n%s", stderr)
	return m[1]
}

// TestE2E_AdapterReplaySameCommit pins the CI rerun contract through the
// adapter binary: a byte-identical rerun of the same commit replays the first
// report, exits with the same verdict, and names the first report id, while
// the same bytes at another commit ingest as a new report.
func TestE2E_AdapterReplaySameCommit(t *testing.T) {
	slug := newProject(t, "adapter-replay")
	key := mintKey(t, slug)
	const commit = "abcdef1234567890abcdef1234567890abcdef12"
	const otherCommit = "1234567890abcdef1234567890abcdef12345678"

	run := func(sha string) (string, string, int) {
		return runBin(t, adapterBin,
			[]string{"API_URL=" + baseURL, "API_KEY=" + key},
			"-project", slug, "-tool", "sarif", "-commit", sha,
			"-file", absFixture(t, "high.sarif.json"))
	}

	_, stderr1, exit1 := run(commit)
	require.Equal(t, 1, exit1, "the blocking finding fails the gate; stderr:\n%s", stderr1)
	require.Contains(t, stderr1, "gate FAILED: 1 blocking finding(s)")
	firstID := reportIDFromAdapter(t, stderr1)

	_, stderr2, exit2 := run(commit)
	require.Equal(t, exit1, exit2, "a rerun of the same commit exits with the same code; stderr:\n%s", stderr2)
	require.Contains(t, stderr2, "gate FAILED: 1 blocking finding(s)",
		"the replayed verdict matches the first run")
	require.Equal(t, firstID, reportIDFromAdapter(t, stderr2),
		"the second run names the first report id")

	_, stderr3, exit3 := run(otherCommit)
	require.Equal(t, 1, exit3, "same bytes at another commit ingest as a new report; stderr:\n%s", stderr3)
	require.NotEqual(t, firstID, reportIDFromAdapter(t, stderr3),
		"another commit gets a new report, not a replay")
}
