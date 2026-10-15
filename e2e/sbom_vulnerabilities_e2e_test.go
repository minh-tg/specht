//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_GrypeCycloneDXAndGrypeJSONAreTheSameFindings walks the story behind Grype's CycloneDX
// output: a pipeline sends it as an SBOM and used to get a clean scan with no findings, though the
// file listed the vulnerabilities. It now lands as findings, and the same scan sent as Grype's own
// JSON adds no second copy.
func TestE2E_GrypeCycloneDXAndGrypeJSONAreTheSameFindings(t *testing.T) {
	slug := newProject(t, "sbom-vulnerabilities")

	status, got := postReport(t, slug, "sbom", readFixture(t, "..", "internal", "parser", "sbom", "testdata", "grype-cyclonedx.json"))
	require.Equal(t, http.StatusCreated, status, got.Error.Message)
	first := request[[]map[string]any](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/findings?limit=50", adminToken, nil, http.StatusOK)
	require.Len(t, first, 3, "the vulnerabilities in the CycloneDX file are findings")
	for _, f := range first {
		require.Equal(t, "sca", f["finding_kind"])
	}

	status, got = postReport(t, slug, "grype", readFixture(t, "..", "internal", "parser", "grype", "testdata", "grype-same-scan.json"))
	require.Equal(t, http.StatusCreated, status, got.Error.Message)
	second := request[[]map[string]any](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/findings?limit=50", adminToken, nil, http.StatusOK)
	require.Len(t, second, 3, "the same scan from Grype adds no second copy")

	ids := map[any]bool{}
	for _, f := range first {
		ids[f["id"]] = true
	}
	for _, f := range second {
		require.True(t, ids[f["id"]], "finding %v is the one the CycloneDX file created", f["id"])
	}
}
