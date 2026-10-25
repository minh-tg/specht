//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// grypeRun returns the real directory scan in the Grype fixtures, with the
// configuration an unfiltered run records and the given matches kept.
func grypeRun(t *testing.T, keepMatches bool, configuration map[string]any) []byte {
	t.Helper()
	var doc map[string]any
	require.NoError(t, json.Unmarshal(
		readFixture(t, "..", "internal", "parser", "grype", "testdata", "grype-same-scan.json"), &doc))
	if !keepMatches {
		doc["matches"] = []any{}
	}
	doc["descriptor"].(map[string]any)["configuration"] = configuration
	out, err := json.Marshal(doc)
	require.NoError(t, err)
	return out
}

// TestE2E_GrypeCleanScanClosesFindings walks a directory scan that reported
// vulnerabilities and the rescan after they were fixed. The clean report has
// no matches to read a location from, so the source block is what makes it
// the same scan.
func TestE2E_GrypeCleanScanClosesFindings(t *testing.T) {
	unfiltered := map[string]any{"only-fixed": false, "only-notfixed": false, "ignore": []any{}, "exclude": []any{}}
	filtered := map[string]any{"only-fixed": true, "only-notfixed": false, "ignore": []any{}, "exclude": []any{}}

	t.Run("an unfiltered clean rescan closes the findings", func(t *testing.T) {
		slug := newProject(t, "grype-clean")
		status, got := postReport(t, slug, "grype", grypeRun(t, true, unfiltered))
		require.Equal(t, http.StatusCreated, status, got.Error.Message)
		before := listScanFindings(t, slug)
		require.Len(t, before, 3)
		for _, f := range before {
			require.Equal(t, "open", f.State)
		}

		status, got = postReport(t, slug, "grype", grypeRun(t, false, unfiltered))
		require.Equal(t, http.StatusCreated, status, got.Error.Message)
		after := listScanFindings(t, slug)
		require.Len(t, after, 3, "absence never deletes findings")
		for _, f := range after {
			require.Equal(t, "fixed", f.State)
		}
	})

	t.Run("a clean rescan that hid matches closes nothing", func(t *testing.T) {
		slug := newProject(t, "grype-filtered")
		status, got := postReport(t, slug, "grype", grypeRun(t, true, unfiltered))
		require.Equal(t, http.StatusCreated, status, got.Error.Message)

		status, got = postReport(t, slug, "grype", grypeRun(t, false, filtered))
		require.Equal(t, http.StatusCreated, status, got.Error.Message)
		for _, f := range listScanFindings(t, slug) {
			require.Equal(t, "open", f.State, "a run with only-fixed set may have hidden the matches")
		}
	})
}
