//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_SemgrepJSONAndSARIFAreTheSameFindings walks the story behind taking Semgrep's own JSON
// output: a project sends semgrep --json, later switches its pipeline to --sarif for the same
// code, and keeps one history instead of a second copy of every finding.
func TestE2E_SemgrepJSONAndSARIFAreTheSameFindings(t *testing.T) {
	slug := newProject(t, "semgrep-formats")
	dir := []string{"..", "internal", "parser", "semgrep", "testdata"}

	status, got := postReport(t, slug, "semgrep", readFixture(t, append(dir, "semgrep-native.json")...))
	require.Equal(t, http.StatusCreated, status, got.Error.Message)
	first := listFindings(t, slug)
	require.Len(t, first, 3, "semgrep --json lands as findings")

	status, got = postReport(t, slug, "semgrep", readFixture(t, append(dir, "semgrep-native-sarif.json")...))
	require.Equal(t, http.StatusCreated, status, got.Error.Message)
	second := listFindings(t, slug)
	require.Len(t, second, 3, "the same scan as SARIF adds no second copy")

	ids := map[string]bool{}
	for _, f := range first {
		ids[f.ID] = true
	}
	for _, f := range second {
		require.True(t, ids[f.ID], "finding %s is the same finding as before", f.ID)
	}
}
