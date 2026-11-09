//go:build e2e

package e2e

import (
	"net/http"
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
