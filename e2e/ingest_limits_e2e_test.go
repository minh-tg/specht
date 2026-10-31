//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// trivyOfEmptyVulnerabilities holds n findings with nothing but a title. The
// title is long enough that the document is not refused for packing too many
// small values into its size, which would hide the finding count under test.
func trivyOfEmptyVulnerabilities(n int) []byte {
	units := strings.TrimSuffix(strings.Repeat(`{"Title":"`+strings.Repeat("x", 24)+`"},`, n), ",")
	return []byte(`{"ArtifactName":"a","Results":[{"Target":"t","Vulnerabilities":[` + units + `]}]}`)
}

// TestE2E_AReportPastTheFindingLimitIsRefused sends reports of minimal findings
// past the default INGEST_MAX_FINDINGS. Both are refused with a 422 that names
// the limit and says to split the report, and nothing is stored.
func TestE2E_AReportPastTheFindingLimitIsRefused(t *testing.T) {
	slug := newProject(t, "finding-limit")

	for name, n := range map[string]int{
		"one finding past the limit, stopped while converting": 100001,
		"far past the limit, refused before decoding":          500_000,
	} {
		t.Run(name, func(t *testing.T) {
			status, got := postReport(t, slug, "trivy", trivyOfEmptyVulnerabilities(n))
			require.Equal(t, http.StatusUnprocessableEntity, status)
			require.Equal(t, "too_many_findings", got.Error.Code)
			require.Contains(t, got.Error.Message, "100000")
			require.Contains(t, got.Error.Message, "Split")
		})
	}

	require.Empty(t, listFindings(t, slug), "a refused report stores nothing")
}
