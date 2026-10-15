//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_CheckovRunOverSeveralFrameworksIsOneReport walks the story behind checkov -d . in a real
// repository: Terraform, Kubernetes and a Dockerfile in one directory give an array with one report
// per framework. It used to be refused outright.
func TestE2E_CheckovRunOverSeveralFrameworksIsOneReport(t *testing.T) {
	slug := newProject(t, "checkov-frameworks")

	status, got := postReport(t, slug, "checkov", readFixture(t, "..", "internal", "parser", "checkov", "testdata", "checkov-multi.json"))
	require.Equal(t, http.StatusCreated, status, got.Error.Message)

	findings := request[[]map[string]any](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/findings?limit=50", adminToken, nil, http.StatusOK)
	require.Len(t, findings, 6, "two failed checks from each of three frameworks")
	for _, f := range findings {
		require.Equal(t, "iac", f["finding_kind"])
	}
}
