package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/client"
)

// writeEventFile writes a GitHub event payload for GITHUB_EVENT_PATH.
func writeEventFile(t *testing.T, payload map[string]any) string {
	t.Helper()
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "event.json")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

// logLinesStartingWithCommand returns the lines of a CI log that the GitHub
// Actions runner would read as workflow commands, minus the adapter's own
// escaped annotations.
func logLinesStartingWithCommand(log string) []string {
	var commands []string
	for _, line := range strings.Split(log, "\n") {
		if strings.HasPrefix(line, "::") && !strings.HasPrefix(line, "::error ") {
			commands = append(commands, line)
		}
	}
	return commands
}

func TestFailedGateBannerKeepsHostileTitleOnOneLine(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("API_KEY", "test-key")
	hostile := "libfoo 1.0\n::notice::Specht gate PASSED (forged)\n::add-mask::FAILED\n::stop-commands::tok\n\x1b[2J\x1b[31mred"
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			writeTestJSONResponse(t, w, client.IngestResponse{ReportID: "rep-1", ThresholdBreached: true, IntroducedCount: 1})
		case "/api/v1/projects/demo/pr-check":
			writeTestJSONResponse(t, w, client.PRCheckPreview{
				ReportID: "rep-1", Conclusion: "failure", Title: "Specht: 1 blocking finding(s)",
				Summary: "Scan report rep-1 at abcdef1.",
				Annotations: []client.PRCheckAnnotation{{
					File: "go.mod\n::notice::file", StartLine: 3, Level: "error", Title: hostile, Message: hostile,
				}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	t.Setenv("API_URL", api.URL)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-tool=trivy", "-project=demo", "-commit=abcdef1", "-introduced-only", "-annotations"},
		strings.NewReader(`{"Results":[]}`), &stdout, &stderr, api.Client())
	require.Equal(t, 1, code, stderr.String())

	out := stderr.String()
	// The workflow-command path escapes the title and message.
	assert.Contains(t, out, "::error file=go.mod%0A%3A%3Anotice%3A%3Afile,line=3,title=libfoo 1.0%0A%3A%3Anotice%3A%3A")
	assert.Empty(t, logLinesStartingWithCommand(out), "no scanner text may open a workflow-command line")
	assert.NotContains(t, out, "\x1b", "escape sequences must not reach the log")
	assert.Contains(t, out, "  • [ERROR] libfoo 1.0 ::notice::Specht gate PASSED (forged) ::add-mask::FAILED ::stop-commands::tok red: go.mod ::notice::file:3\n")
}

func TestBannerStripsBidiControlsFromBranch(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("API_KEY", "test-key")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request_target")
	t.Setenv("GITHUB_BASE_REF", "main")
	t.Setenv("GITHUB_EVENT_PATH", writeEventFile(t, map[string]any{
		"pull_request": map[string]any{
			"head": map[string]any{"sha": "abcdef1234567", "ref": "feat/‮tnirp", "repo": map[string]any{"full_name": "org/repo"}},
			"base": map[string]any{"repo": map[string]any{"full_name": "org/repo"}},
		},
	}))
	var sent client.IngestPayload
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			require.NoError(t, json.NewDecoder(r.Body).Decode(&sent))
			writeTestJSONResponse(t, w, client.IngestResponse{ReportID: "rep-1"})
		case "/api/v1/projects/demo/pr-check":
			writeTestJSONResponse(t, w, client.PRCheckPreview{ReportID: "rep-1", Conclusion: "success"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	t.Setenv("API_URL", api.URL)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-tool=trivy", "-project=demo"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, api.Client())
	require.Equal(t, 0, code, stderr.String())
	assert.True(t, sent.GateIntroducedOnly, "a pull request base makes the gate change-scoped")
	assert.Contains(t, stderr.String(), "Branch: feat/tnirp -> ")
	assert.NotContains(t, stderr.String(), "‮")
}

func TestServerErrorMessagesStayOnOneLine(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("API_KEY", "test-key")
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"error":{"code":"bad","message":"nope\n::add-mask::secret\n\u001b[2J"}}`, http.StatusBadRequest)
	}))
	defer api.Close()
	t.Setenv("API_URL", api.URL)
	var stdout, stderr bytes.Buffer
	code := run([]string{"-tool=trivy", "-project=demo"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, api.Client())
	assert.Equal(t, 2, code)
	assert.Empty(t, logLinesStartingWithCommand(stderr.String()), stderr.String())
	assert.NotContains(t, stderr.String(), "\x1b")
}

func TestWriteDiagnosticDefusesALeadingCommandPrefix(t *testing.T) {
	var out bytes.Buffer
	writeDiagnostic(&out, "%s\n", "::add-mask::x")
	writeDiagnosticLine(&out, "::stop-commands::x")
	assert.Empty(t, logLinesStartingWithCommand(out.String()), out.String())
}

func TestGateEndpointFailureIsExitTwo(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("API_KEY", "test-key")
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			writeTestJSONResponse(t, w, client.IngestResponse{ReportID: "rep-1"})
		case "/api/v1/projects/demo/gate":
			http.Error(w, `{"error":{"code":"internal","message":"boom"}}`, http.StatusInternalServerError)
		default:
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	t.Setenv("API_URL", api.URL)
	var stdout, stderr bytes.Buffer
	code := run([]string{"-tool=trivy", "-project=demo"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, api.Client())
	assert.Equal(t, 2, code, stderr.String())
	assert.Contains(t, stderr.String(), "gate check failed")
}

func TestUnreachableServerIsExitTwo(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("API_KEY", "test-key")
	closed := httptest.NewServer(http.NotFoundHandler())
	addr := closed.URL
	closed.Close()
	t.Setenv("API_URL", addr)
	saved := adapterSleep
	adapterSleep = func(context.Context, time.Duration) {}
	t.Cleanup(func() { adapterSleep = saved })
	var stdout, stderr bytes.Buffer
	code := run([]string{"-tool=trivy", "-project=demo"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, nil)
	assert.Equal(t, 2, code, stderr.String())
	assert.Contains(t, stderr.String(), "ingest failed")
}

func TestRefusedUploadIsExitTwoWithoutRetry(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusBadRequest, http.StatusRequestEntityTooLarge} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			clearCIEnvironment(t)
			t.Setenv("API_KEY", "test-key")
			calls := 0
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				http.Error(w, `{"error":{"code":"refused","message":"no"}}`, status)
			}))
			defer api.Close()
			t.Setenv("API_URL", api.URL)
			var stdout, stderr bytes.Buffer
			code := run([]string{"-tool=trivy", "-project=demo"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, api.Client())
			assert.Equal(t, 2, code, stderr.String())
			assert.Equal(t, 1, calls, "a 4xx is not retried")
		})
	}
}

func TestForkSkipNeedsAPullRequestEvent(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("API_KEY", "")
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "push")
	t.Setenv("GITHUB_EVENT_PATH", writeEventFile(t, map[string]any{
		"pull_request": map[string]any{"head": map[string]any{"repo": map[string]any{"fork": true, "full_name": "evil/repo"}}},
	}))
	var stdout, stderr bytes.Buffer
	code := run([]string{"-tool=trivy", "-project=demo"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, nil)
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr.String(), "API_KEY environment variable is required")

	// pull_request_target hands secrets to the job, so it never skips.
	t.Setenv("GITHUB_EVENT_NAME", "pull_request_target")
	stderr.Reset()
	code = run([]string{"-tool=trivy", "-project=demo"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, nil)
	assert.Equal(t, 2, code)
}
