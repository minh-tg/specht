//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

type refusal struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// postReport sends raw document bytes under a scanner name and returns the status and the error body.
func postReport(t *testing.T, slug, scanner string, document []byte) (int, refusal) {
	t.Helper()
	status, body := doJSON(t, http.MethodPost, "/api/v1/reports", adminToken, map[string]any{
		"project": slug, "scanner": scanner, "raw_data": json.RawMessage(document),
	})
	var r refusal
	_ = json.Unmarshal(body, &r)
	return status, r
}

func readFixture(t *testing.T, path ...string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(path...))
	require.NoError(t, err)
	return data
}

// TestE2E_AFileSentUnderTheWrongScannerIsRefused walks the story behind the format check: someone
// picks the wrong scanner in the dropdown. The upload is refused with a message that says what to
// pick, nothing is stored, and clean reports of the right format still go through.
func TestE2E_AFileSentUnderTheWrongScannerIsRefused(t *testing.T) {
	slug := newProject(t, "format-check")

	t.Run("another supported tool's output names the scanner it looks like", func(t *testing.T) {
		status, got := postReport(t, slug, "trivy", readFixture(t, "testdata", "grype-report.json"))
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Equal(t, "unrecognized_format", got.Error.Code)
		require.Contains(t, got.Error.Message, "choose grype")
	})

	t.Run("output of a tool with no parser says to check the scanner", func(t *testing.T) {
		status, got := postReport(t, slug, "trivy", readFixture(t, "..", "internal", "parser", "testdata", "foreign", "gosec.json"))
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Equal(t, "unrecognized_format", got.Error.Code)
		require.Contains(t, got.Error.Message, "Check that you chose the scanner")
	})

	t.Run("SARIF of another tool belongs to the generic sarif scanner", func(t *testing.T) {
		document := readFixture(t, "testdata", "high.sarif.json")
		status, got := postReport(t, slug, "semgrep", document)
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Equal(t, "unrecognized_format", got.Error.Code)

		status, _ = postReport(t, slug, "sarif", document)
		require.Equal(t, http.StatusCreated, status)
	})

	t.Run("an unknown scanner is named and points at the list", func(t *testing.T) {
		status, got := postReport(t, slug, "no-such-tool", []byte(`{}`))
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Equal(t, "unknown_scanner", got.Error.Code)
		require.Contains(t, got.Error.Message, "no-such-tool")
	})

	t.Run("a refused upload leaves no report behind", func(t *testing.T) {
		clean := newProject(t, "format-check-clean")
		for _, scanner := range []string{"trivy", "osv-scanner", "grype", "dependency-check", "checkov", "tfsec", "gitleaks", "nuclei", "semgrep", "sbom"} {
			status, _ := postReport(t, clean, scanner, readFixture(t, "..", "internal", "parser", "testdata", "foreign", "npm-audit.json"))
			require.Equal(t, http.StatusUnprocessableEntity, status, scanner)
		}
		reports := request[[]map[string]any](t, http.MethodGet, "/api/v1/projects/"+clean+"/reports", adminToken, nil, http.StatusOK)
		require.Empty(t, reports)
		require.Empty(t, listFindings(t, clean))
	})

	t.Run("a clean report of every supported tool is accepted", func(t *testing.T) {
		clean := newProject(t, "format-check-empty")
		for scanner, document := range map[string]string{
			"trivy":            string(readFixture(t, "testdata", "trivy-empty-scan.json")),
			"osv-scanner":      `{"results":[]}`,
			"grype":            `{"matches":[],"source":{},"distro":{},"descriptor":{"name":"grype","version":"0.120.0"}}`,
			"dependency-check": `{"reportSchema":"1.1","scanInfo":{},"dependencies":[]}`,
			"semgrep":          `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS"}},"results":[]}]}`,
			"sarif":            `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"codeql"}},"results":[]}]}`,
			"checkov":          string(readFixture(t, "..", "internal", "parser", "checkov", "testdata", "checkov-empty.json")),
			"tfsec":            `{"results":null}`,
			"gitleaks":         `[]`,
			"nuclei":           `[]`,
			"sbom":             `{"bomFormat":"CycloneDX","specVersion":"1.5"}`,
		} {
			status, got := postReport(t, clean, scanner, []byte(document))
			require.Equal(t, http.StatusCreated, status, "%s: %s %s", scanner, got.Error.Code, got.Error.Message)
		}
	})
}
