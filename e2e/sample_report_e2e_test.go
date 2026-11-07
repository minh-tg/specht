//go:build e2e

package e2e

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_SampleReportShowsAVerdict pins the report the CI setup page sends: it
// has to parse as Trivy output, block, and offer fixes, or the first thing a new
// user sees is an error or a green page.
func TestE2E_SampleReportShowsAVerdict(t *testing.T) {
	sample, err := filepath.Abs("../frontend/public/sample-trivy-report.json")
	require.NoError(t, err)
	slug := newProject(t, "sample")
	key := mintKey(t, slug)
	_, stderr, exit := runBin(t, adapterBin, []string{"API_URL=" + baseURL, "API_KEY=" + key},
		"-project", slug, "-tool", "trivy", "-branch", "main",
		"-commit", "1111111111111111111111111111111111111111", "-file", sample)
	require.Equal(t, 1, exit, stderr)
	require.Contains(t, stderr, "gate FAILED: 2 blocking finding(s)")
	require.Len(t, listFindings(t, slug), 3)
}
