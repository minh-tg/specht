package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/client"
)

func writePullRequestEvent(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "event.json")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))
	t.Setenv("GITHUB_EVENT_PATH", path)
}

func TestApplyCIContext_GitHubPullRequest(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "acme/shop")
	t.Setenv("GITHUB_RUN_ID", "42")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	writePullRequestEvent(t, `{"pull_request":{"number":123,"title":"Bump lodash","head":{"sha":"abc","ref":"bump"}}}`)

	var payload client.IngestPayload
	var stderr bytes.Buffer
	applyCIContext(&payload, &adapterFlags{}, &stderr)

	assert.Equal(t, "https://github.com/acme/shop", payload.RepositoryURL)
	assert.Equal(t, "https://github.com/acme/shop/actions/runs/42", payload.CIRunURL)
	assert.Equal(t, int64(123), payload.PullRequestNumber)
	assert.Equal(t, "Bump lodash", payload.PullRequestTitle)
	assert.Empty(t, stderr.String())
}

func TestApplyCIContext_GitHubPushHasNoPullRequest(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("GITHUB_SERVER_URL", "https://github.com")
	t.Setenv("GITHUB_REPOSITORY", "acme/shop")
	t.Setenv("GITHUB_RUN_ID", "43")
	t.Setenv("GITHUB_EVENT_NAME", "push")
	writePullRequestEvent(t, `{"pull_request":{"number":9,"title":"stale","head":{"sha":"abc","ref":"x"}}}`)

	var payload client.IngestPayload
	applyCIContext(&payload, &adapterFlags{}, &bytes.Buffer{})

	assert.Equal(t, "https://github.com/acme/shop", payload.RepositoryURL)
	assert.Zero(t, payload.PullRequestNumber, "a push build names no pull request")
	assert.Empty(t, payload.PullRequestTitle)
}

func TestApplyCIContext_GitLabMergeRequest(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("GITLAB_CI", "true")
	t.Setenv("CI_PROJECT_URL", "https://gitlab.example.com/acme/shop")
	t.Setenv("CI_REPOSITORY_URL", "https://gitlab-ci-token:glcbt-secret@gitlab.example.com/acme/shop.git")
	t.Setenv("CI_JOB_URL", "https://gitlab.example.com/acme/shop/-/jobs/77")
	t.Setenv("CI_MERGE_REQUEST_IID", "15")
	t.Setenv("CI_MERGE_REQUEST_TITLE", "Draft: fix the cart")

	var payload client.IngestPayload
	var stderr bytes.Buffer
	applyCIContext(&payload, &adapterFlags{}, &stderr)

	assert.Equal(t, "https://gitlab.example.com/acme/shop", payload.RepositoryURL, "the web URL, never the clone URL with the token")
	assert.Equal(t, "https://gitlab.example.com/acme/shop/-/jobs/77", payload.CIRunURL)
	assert.Equal(t, int64(15), payload.PullRequestNumber)
	assert.Equal(t, "Draft: fix the cart", payload.PullRequestTitle)
	assert.NotContains(t, stderr.String(), "glcbt-secret")
}

func TestApplyCIContext_FlagsWinOverCI(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("CI_PROJECT_URL", "https://gitlab.example.com/acme/shop")
	t.Setenv("CI_MERGE_REQUEST_IID", "15")

	var payload client.IngestPayload
	applyCIContext(&payload, &adapterFlags{
		repoURL: "https://git.example.org/acme/shop", pullRequest: 8, runURL: "https://ci.example.org/runs/3",
	}, &bytes.Buffer{})

	assert.Equal(t, "https://git.example.org/acme/shop", payload.RepositoryURL)
	assert.Equal(t, int64(8), payload.PullRequestNumber)
	assert.Equal(t, "https://ci.example.org/runs/3", payload.CIRunURL)
}

// A value the server would refuse is dropped with a note, and the upload
// still goes ahead.
func TestApplyCIContext_DropsWhatTheServerWouldRefuse(t *testing.T) {
	clearCIEnvironment(t)
	var payload client.IngestPayload
	var stderr bytes.Buffer
	applyCIContext(&payload, &adapterFlags{
		repoURL: "https://user:hunter2@git.example.org/acme/shop", runURL: "ftp://ci.example.org/run",
	}, &stderr)

	assert.Empty(t, payload.RepositoryURL)
	assert.Empty(t, payload.CIRunURL)
	assert.Contains(t, stderr.String(), "repository URL is not sent")
	assert.Contains(t, stderr.String(), "CI run URL is not sent")
	assert.NotContains(t, stderr.String(), "hunter2", "a note never prints the credential")
}

func TestCleanTitle(t *testing.T) {
	assert.Equal(t, "fix  the cart", cleanTitle("fix\n\tthe cart\x00"))
	long := strings.Repeat("é", 300) // 600 bytes
	got := cleanTitle(long)
	assert.LessOrEqual(t, len(got), 512)
	assert.True(t, strings.HasPrefix(long, got))
	assert.Equal(t, 256, len([]rune(got)), "the cut lands on a character boundary")
}

// A value in the input envelope wins over what the CI provider sets, and the
// whole chain runs inside buildPayload.
func TestBuildPayload_EnvelopeCIContextWinsOverCI(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("CI_PROJECT_URL", "https://gitlab.example.com/acme/shop")
	t.Setenv("CI_JOB_URL", "https://gitlab.example.com/acme/shop/-/jobs/77")
	raw := []byte(`{"scanner":"trivy","raw_data":{"SchemaVersion":2},"repository_url":"https://git.example.org/acme/shop"}`)

	payload := buildTestPayload(t, raw, &adapterFlags{})

	assert.Equal(t, "https://git.example.org/acme/shop", payload.RepositoryURL)
	assert.Equal(t, "https://gitlab.example.com/acme/shop/-/jobs/77", payload.CIRunURL)
}
