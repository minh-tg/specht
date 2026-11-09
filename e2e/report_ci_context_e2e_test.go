//go:build e2e

package e2e

import (
	"net/http"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestE2E_ReportKeepsWhereItCameFrom sends the repository, pull request and
// run with a report and reads them back, and checks that a repository URL with
// a CI token in it is refused before anything is stored.
func TestE2E_ReportKeepsWhereItCameFrom(t *testing.T) {
	slug := newProject(t, "ci-context")
	key := mintKey(t, slug)

	created := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high-medium.sarif.json", map[string]any{
			"commit_sha":          "3333333333333333333333333333333333333333",
			"repository_url":      "https://github.com/acme/shop",
			"pull_request_number": 123,
			"pull_request_title":  "Bump lodash",
			"ci_run_url":          "https://github.com/acme/shop/actions/runs/42",
		}), http.StatusCreated)

	type ciContext struct {
		RepositoryURL     string `json:"repository_url"`
		PullRequestNumber int    `json:"pull_request_number"`
		PullRequestTitle  string `json:"pull_request_title"`
		CIRunURL          string `json:"ci_run_url"`
	}
	got := request[ciContext](t, http.MethodGet, "/api/v1/reports/"+created.ReportID, adminToken, nil, http.StatusOK)
	assert.Equal(t, ciContext{
		RepositoryURL:     "https://github.com/acme/shop",
		PullRequestNumber: 123,
		PullRequestTitle:  "Bump lodash",
		CIRunURL:          "https://github.com/acme/shop/actions/runs/42",
	}, got)

	status, body := doJSON(t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high-medium.sarif.json", map[string]any{
			"commit_sha":     "4444444444444444444444444444444444444444",
			"repository_url": "https://gitlab-ci-token:glcbt-secret@gitlab.com/acme/shop.git",
		}))
	require.Equal(t, http.StatusBadRequest, status, "%s", body)
	assert.Contains(t, string(body), "repository_url")
	assert.NotContains(t, string(body), "glcbt-secret", "the refusal must not echo the token")
}

// TestE2E_AdapterSendsWhereTheReportCameFrom runs the adapter with the
// variables a GitLab merge request pipeline sets and reads them back from the
// stored report. The job token in CI_REPOSITORY_URL must never reach it.
func TestE2E_AdapterSendsWhereTheReportCameFrom(t *testing.T) {
	semgrep, err := filepath.Abs("../internal/parser/semgrep/testdata/semgrep-sarif.json")
	require.NoError(t, err)
	slug := newProject(t, "ci-context-adapter")
	key := mintKey(t, slug)

	_, stderr, exit := runBin(t, adapterBin, []string{
		"API_URL=" + baseURL, "API_KEY=" + key, "GITLAB_CI=true",
		"CI_PROJECT_URL=https://gitlab.example.com/acme/shop",
		"CI_REPOSITORY_URL=https://gitlab-ci-token:glcbt-secret@gitlab.example.com/acme/shop.git",
		"CI_JOB_URL=https://gitlab.example.com/acme/shop/-/jobs/77",
		"CI_MERGE_REQUEST_IID=15", "CI_MERGE_REQUEST_TITLE=Fix the cart",
	}, "-project", slug, "-tool", "semgrep", "-branch", "fix/cart",
		"-commit", "5555555555555555555555555555555555555555", "-file", semgrep)
	require.Less(t, exit, 2, stderr)
	assert.NotContains(t, stderr, "glcbt-secret")

	status, raw := doJSON(t, http.MethodGet, "/api/v1/projects/"+slug+"/reports", adminToken, nil)
	require.Equal(t, http.StatusOK, status, "%s", raw)
	assert.Contains(t, string(raw), `"repository_url":"https://gitlab.example.com/acme/shop"`)
	assert.Contains(t, string(raw), `"pull_request_number":15`)
	assert.Contains(t, string(raw), `"pull_request_title":"Fix the cart"`)
	assert.Contains(t, string(raw), `"ci_run_url":"https://gitlab.example.com/acme/shop/-/jobs/77"`)
	assert.NotContains(t, string(raw), "glcbt-secret")
}
