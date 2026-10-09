package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func writeTestJSONResponse(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode test response: %v", err)
	}
}

func TestBuildPayload_PreservesNonEnvelopeScannerOutput(t *testing.T) {
	raw := []byte(`{"Results":`)
	flags := &adapterFlags{project: "my-app", tool: "trivy"}
	var stderr bytes.Buffer

	payload, code := buildPayload(raw, flags, &stderr)
	require.Zero(t, code)
	assert.Equal(t, "my-app", payload.Project)
	assert.Equal(t, "trivy", payload.Scanner)
	assert.Equal(t, json.RawMessage(raw), payload.RawData)
	assert.Empty(t, stderr.String())
}

func TestNormalizeRawJSON(t *testing.T) {
	t.Run("preserves valid single object", func(t *testing.T) {
		input := []byte(`{"Results": []}`)
		got := normalizeRawJSON(input)
		assert.Equal(t, input, got)
	})

	t.Run("preserves valid single array", func(t *testing.T) {
		input := []byte(`[{"id": 1}, {"id": 2}]`)
		got := normalizeRawJSON(input)
		assert.Equal(t, input, got)
	})

	t.Run("normalizes line-delimited json into array", func(t *testing.T) {
		input := []byte("{\"check_id\": \"rule-1\", \"file\": \"a.go\"}\n{\"check_id\": \"rule-2\", \"file\": \"b.go\"}\n")
		got := normalizeRawJSON(input)
		require.True(t, json.Valid(got))

		var items []map[string]string
		require.NoError(t, json.Unmarshal(got, &items))
		require.Len(t, items, 2)
		assert.Equal(t, "rule-1", items[0]["check_id"])
		assert.Equal(t, "rule-2", items[1]["check_id"])
	})

	t.Run("handles crlf and blank lines", func(t *testing.T) {
		input := []byte("\r\n{\"id\": 1}\r\n\r\n{\"id\": 2}\r\n{\"id\": 3}\r\n")
		got := normalizeRawJSON(input)
		require.True(t, json.Valid(got))

		var items []map[string]int
		require.NoError(t, json.Unmarshal(got, &items))
		require.Len(t, items, 3)
		assert.Equal(t, 1, items[0]["id"])
		assert.Equal(t, 2, items[1]["id"])
		assert.Equal(t, 3, items[2]["id"])
	})

	t.Run("preserves malformed or non-json input", func(t *testing.T) {
		malformed := []byte("not valid json\nat all")
		assert.Equal(t, malformed, normalizeRawJSON(malformed))

		partial := []byte("{\"incomplete\":")
		assert.Equal(t, partial, normalizeRawJSON(partial))

		empty := []byte("   \n\t  ")
		assert.Equal(t, empty, normalizeRawJSON(empty))
	})
}

func TestBuildPayload_NormalizesLineDelimitedJSON(t *testing.T) {
	raw := []byte("{\"template-id\": \"cve-1\", \"host\": \"example.com\"}\n{\"template-id\": \"cve-2\", \"host\": \"example.com\"}\n")
	flags := &adapterFlags{project: "my-app", tool: "nuclei"}
	var stderr bytes.Buffer

	payload, code := buildPayload(raw, flags, &stderr)
	require.Zero(t, code)
	assert.Equal(t, "my-app", payload.Project)
	assert.Equal(t, "nuclei", payload.Scanner)
	require.True(t, json.Valid(payload.RawData))

	var parsed []map[string]string
	require.NoError(t, json.Unmarshal(payload.RawData, &parsed))
	require.Len(t, parsed, 2)
	assert.Equal(t, "cve-1", parsed[0]["template-id"])
	assert.Equal(t, "cve-2", parsed[1]["template-id"])
}

func TestRun_LineDelimitedJSON_IngestSuccess(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("API_KEY", "test-key")

	var captured client.IngestPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			require.NoError(t, json.NewDecoder(r.Body).Decode(&captured))
			writeTestJSONResponse(t, w, client.IngestResponse{
				ReportID:          "rep-jsonl",
				TotalFindings:     2,
				ThresholdBreached: false,
			})
		case "/api/v1/projects/my-app/gate":
			writeTestJSONResponse(t, w, client.GateStatus{
				ThresholdBreached: false,
				BlockingCount:     0,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("API_URL", srv.URL)

	jsonlInput := "{\"template-id\": \"t1\", \"host\": \"localhost\"}\n{\"template-id\": \"t2\", \"host\": \"localhost\"}\n"
	var stdout, stderr bytes.Buffer
	args := []string{"-project=my-app", "-tool=nuclei"}
	code := run(args, strings.NewReader(jsonlInput), &stdout, &stderr, srv.Client())

	assert.Equal(t, 0, code)
	assert.Equal(t, "my-app", captured.Project)
	assert.Equal(t, "nuclei", captured.Scanner)
	require.True(t, json.Valid(captured.RawData))
	assert.Contains(t, stderr.String(), "report rep-jsonl ingested, 2 finding(s)")
	assert.Contains(t, stderr.String(), "gate PASSED")
}

func TestIngestReport_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, "/api/v1/reports", r.URL.Path)
		assert.Equal(t, "Bearer test-key", r.Header.Get("Authorization"))

		if err := json.NewEncoder(w).Encode(client.IngestResponse{
			ReportID:          "rep-123",
			TotalFindings:     3,
			ThresholdBreached: false,
		}); err != nil {
			t.Errorf("encode ingest response: %v", err)
		}
	}))
	defer srv.Close()

	cl := client.New(srv.URL, client.WithToken("test-key"))
	resp, err := cl.IngestReport(&client.IngestPayload{
		Project: "my-app",
		Scanner: "trivy",
		RawData: json.RawMessage(`{"image":"test"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, "rep-123", resp.ReportID)
	assert.Equal(t, 3, resp.TotalFindings)
	assert.False(t, resp.ThresholdBreached)
}

func TestIngestReport_ThresholdBreached(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewEncoder(w).Encode(client.IngestResponse{
			ReportID:          "rep-123",
			TotalFindings:     1,
			ThresholdBreached: true,
		}); err != nil {
			t.Errorf("encode ingest response: %v", err)
		}
	}))
	defer srv.Close()

	cl := client.New(srv.URL, client.WithToken("test-key"))
	resp, err := cl.IngestReport(&client.IngestPayload{
		Project: "my-app",
		Scanner: "trivy",
		RawData: json.RawMessage(`{"image":"test"}`),
	})
	require.NoError(t, err)
	assert.True(t, resp.ThresholdBreached)
}

func TestIngestReport_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		if err := json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]string{"code": "ingest_failed", "message": "unknown scanner"},
		}); err != nil {
			t.Errorf("encode error response: %v", err)
		}
	}))
	defer srv.Close()

	cl := client.New(srv.URL, client.WithToken("test-key"))
	_, err := cl.IngestReport(&client.IngestPayload{
		Project: "my-app",
		Scanner: "unknown",
		RawData: json.RawMessage(`{}`),
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown scanner")
}

func TestIngestReport_IntroducedOnly_Payload(t *testing.T) {
	var captured client.IngestPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		err := json.NewDecoder(r.Body).Decode(&captured)
		require.NoError(t, err)

		writeTestJSONResponse(t, w, client.IngestResponse{
			ReportID:          "rep-456",
			TotalFindings:     5,
			ThresholdBreached: false,
			ScanMode:          "full",
			IntroducedCount:   0,
			PreExistingCount:  5,
		})
	}))
	defer srv.Close()

	cl := client.New(srv.URL, client.WithToken("test-key"))
	resp, err := cl.IngestReport(&client.IngestPayload{
		Project:            "my-app",
		Scanner:            "trivy",
		RawData:            json.RawMessage(`{"image":"test"}`),
		BaseRevision:       "main",
		CommitSha:          "abc12345",
		Branch:             "feat/test",
		GateIntroducedOnly: true,
	})
	require.NoError(t, err)
	assert.True(t, captured.GateIntroducedOnly)
	assert.Equal(t, "main", captured.BaseRevision)
	assert.Equal(t, "abc12345", captured.CommitSha)
	assert.Equal(t, "feat/test", captured.Branch)
	assert.Equal(t, 0, resp.IntroducedCount)
	assert.Equal(t, 5, resp.PreExistingCount)
	assert.False(t, resp.ThresholdBreached)
}

func clearCIEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"GITHUB_BASE_REF", "GITHUB_SHA", "GITHUB_REF_NAME",
		"CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "CI_COMMIT_SHA", "CI_COMMIT_REF_NAME",
	} {
		t.Setenv(key, "")
	}
}

func TestDetectCIEnvironment_GitHub(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("GITHUB_BASE_REF", "main")
	t.Setenv("GITHUB_SHA", "commit123")
	t.Setenv("GITHUB_REF_NAME", "feature-branch")

	var baseRef, commit, branch string
	detectCIEnvironment(&baseRef, &commit, &branch)

	assert.Equal(t, "main", baseRef)
	assert.Equal(t, "commit123", commit)
	assert.Equal(t, "feature-branch", branch)
}

func TestDetectCIEnvironment_GitLab(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "master")
	t.Setenv("CI_COMMIT_SHA", "commit456")
	t.Setenv("CI_COMMIT_REF_NAME", "mr-branch")

	var baseRef, commit, branch string
	detectCIEnvironment(&baseRef, &commit, &branch)

	assert.Equal(t, "master", baseRef)
	assert.Equal(t, "commit456", commit)
	assert.Equal(t, "mr-branch", branch)
}

func TestApplyGateFlags_IgnoresDeprecatedStatus(t *testing.T) {
	var payload client.IngestPayload
	applyGateFlags(&payload, &adapterFlags{status: "open", severity: "high"})
	assert.Empty(t, payload.GateStatus, "the deprecated flag must not reach the payload")
	assert.Equal(t, "high", payload.GateSeverity)
}

func TestRun_StatusFlagDeprecated(t *testing.T) {
	var captured []client.IngestPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			var payload client.IngestPayload
			require.NoError(t, json.NewDecoder(r.Body).Decode(&payload))
			captured = append(captured, payload)
			writeTestJSONResponse(t, w, client.IngestResponse{ReportID: "rep-status"})
		case "/api/v1/projects/my-app/gate":
			writeTestJSONResponse(t, w, client.GateStatus{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	clearCIMarkers(t)
	t.Setenv("API_KEY", "test-key")
	t.Setenv("API_URL", srv.URL)

	{
		var stdout, stderr bytes.Buffer
		code := run([]string{"-project=my-app", "-tool=trivy", "-status=open"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, srv.Client())
		require.Equal(t, 0, code, "stderr:\n%s", stderr.String())
		assert.Contains(t, stderr.String(), "-status is deprecated")
	}
	{
		var stdout, stderr bytes.Buffer
		code := run([]string{"-project=my-app", "-tool=trivy"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, srv.Client())
		require.Equal(t, 0, code, "stderr:\n%s", stderr.String())
		assert.NotContains(t, stderr.String(), "-status is deprecated")
	}

	require.Len(t, captured, 2)
	assert.Empty(t, captured[0].GateStatus, "the deprecated flag must not reach the payload")
	assert.Empty(t, captured[1].GateStatus)
}

func TestRun_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-help"}, bytes.NewReader(nil), &stdout, &stderr, nil)
	assert.Equal(t, 0, code)
	assert.Contains(t, stderr.String(), "Usage: specht-adapter")
}

func TestRun_Help_SeverityDescribesPolicyFloor(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-help"}, bytes.NewReader(nil), &stdout, &stderr, nil)
	require.Equal(t, 0, code)
	assert.NotContains(t, stderr.String(), "default: high,critical", "the policy decides the baseline, not the flag")
	assert.Contains(t, stderr.String(), "the project policy decides")
	assert.Contains(t, stderr.String(), "can only tighten")
}

func TestParseFlags_SeverityHelpText(t *testing.T) {
	var stderr bytes.Buffer
	f := parseFlags([]string{"-severity"}, &stderr, false)
	require.Nil(t, f, "a missing flag value fails parsing")
	assert.NotContains(t, stderr.String(), "default: high,critical")
	assert.Contains(t, stderr.String(), "can only tighten")
}

func TestRun_MissingAPIKey(t *testing.T) {
	t.Setenv("API_KEY", "")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=test", "-tool=trivy"}, strings.NewReader(`{}`), &stdout, &stderr, nil)
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr.String(), "API_KEY environment variable is required")
}

func TestRun_MissingAPIURLInCI(t *testing.T) {
	clearCIMarkers(t)
	t.Setenv("CI", "true")
	t.Setenv("API_KEY", "test-key")
	t.Setenv("API_URL", "")
	t.Setenv("SPECHT_API_URL", "")

	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=my-app", "-tool=trivy"}, strings.NewReader(`{}`), &stdout, &stderr, nil)
	require.Equal(t, 2, code)
	assert.Contains(t, stderr.String(), "refusing to default to http://localhost:8080")
}

func TestRun_MissingAPIURLOutsideCIWarns(t *testing.T) {
	clearCIMarkers(t)
	t.Setenv("API_KEY", "test-key")
	t.Setenv("API_URL", "")
	t.Setenv("SPECHT_API_URL", "")

	var stderr bytes.Buffer
	gotURL, code := resolveAPIURL(&stderr)
	require.Zero(t, code)
	assert.Equal(t, "http://localhost:8080", gotURL)
	assert.Contains(t, stderr.String(), "notice: SPECHT_API_URL is not set")
}

func TestResolveAPIURL(t *testing.T) {
	t.Run("API_URL wins over the alias and drops a trailing slash", func(t *testing.T) {
		clearCIMarkers(t)
		t.Setenv("API_URL", "https://a.example.com/")
		t.Setenv("SPECHT_API_URL", "https://b.example.com")
		var stderr bytes.Buffer
		gotURL, code := resolveAPIURL(&stderr)
		require.Zero(t, code)
		assert.Equal(t, "https://a.example.com", gotURL)
		assert.Empty(t, stderr.String())
	})

	t.Run("SPECHT_API_URL is accepted", func(t *testing.T) {
		clearCIMarkers(t)
		t.Setenv("API_URL", "")
		t.Setenv("SPECHT_API_URL", "https://b.example.com/")
		var stderr bytes.Buffer
		gotURL, code := resolveAPIURL(&stderr)
		require.Zero(t, code)
		assert.Equal(t, "https://b.example.com", gotURL)
		assert.Empty(t, stderr.String())
	})

	t.Run("every CI marker rejects a missing URL", func(t *testing.T) {
		for _, marker := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI"} {
			t.Run(marker, func(t *testing.T) {
				clearCIMarkers(t)
				if marker == "CI" {
					t.Setenv("CI", "true")
				} else {
					t.Setenv(marker, "true")
				}
				t.Setenv("API_URL", "")
				t.Setenv("SPECHT_API_URL", "")
				var stderr bytes.Buffer
				gotURL, code := resolveAPIURL(&stderr)
				assert.Equal(t, 2, code)
				assert.Empty(t, gotURL)
				assert.Contains(t, stderr.String(), "refusing to default")
			})
		}
	})
}

func clearCIMarkers(t *testing.T) {
	t.Helper()
	for _, key := range []string{"CI", "GITHUB_ACTIONS", "GITLAB_CI"} {
		t.Setenv(key, "")
	}
}

func writeEventPayload(t *testing.T, value any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "event.json")
	raw, err := json.Marshal(value)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path
}

func tempSummaryFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "summary.md")
	require.NoError(t, os.WriteFile(path, nil, 0o600))
	return path
}

func clearAPIKeyEnv(t *testing.T) {
	t.Helper()
	t.Setenv("API_KEY", "")
	t.Setenv("SPECHT_API_KEY", "")
}

func TestRun_ForkPullRequestSkipsGate(t *testing.T) {
	clearCIMarkers(t)
	clearAPIKeyEnv(t)
	t.Setenv("GITHUB_ACTIONS", "true")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	t.Setenv("API_URL", "")
	t.Setenv("SPECHT_API_URL", "")
	t.Setenv("GITHUB_EVENT_PATH", writeEventPayload(t, map[string]any{
		"pull_request": map[string]any{
			"head": map[string]any{"repo": map[string]any{"fork": true, "full_name": "contributor/specht"}},
			"base": map[string]any{"repo": map[string]any{"full_name": "minh-tg/specht"}},
		},
	}))
	summary := tempSummaryFile(t)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=my-app", "-tool=trivy", "-summary-file=" + summary}, strings.NewReader(`{}`), &stdout, &stderr, nil)
	require.Equal(t, 0, code, "a fork PR must skip, not fail; stderr:\n%s", stderr.String())
	assert.Contains(t, stderr.String(), "from a fork")
	assert.Contains(t, stderr.String(), "skipped")

	got, err := os.ReadFile(summary)
	require.NoError(t, err)
	assert.Contains(t, string(got), "Specht gate skipped")
}

func TestRun_ForkPullRequestDetectedByFullName(t *testing.T) {
	clearCIMarkers(t)
	clearAPIKeyEnv(t)
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	t.Setenv("GITHUB_EVENT_PATH", writeEventPayload(t, map[string]any{
		"pull_request": map[string]any{
			"head": map[string]any{"repo": map[string]any{"fork": false, "full_name": "contributor/specht"}},
			"base": map[string]any{"repo": map[string]any{"full_name": "minh-tg/specht"}},
		},
	}))

	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=my-app", "-tool=trivy"}, strings.NewReader(`{}`), &stdout, &stderr, nil)
	require.Equal(t, 0, code, "stderr:\n%s", stderr.String())
	assert.Contains(t, stderr.String(), "from a fork")
}

func TestRun_NonForkPullRequestMissingKeyFails(t *testing.T) {
	clearCIMarkers(t)
	clearAPIKeyEnv(t)
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	t.Setenv("API_URL", "https://specht.example.com")
	t.Setenv("GITHUB_EVENT_PATH", writeEventPayload(t, map[string]any{
		"pull_request": map[string]any{
			"head": map[string]any{"repo": map[string]any{"fork": false, "full_name": "minh-tg/specht"}},
			"base": map[string]any{"repo": map[string]any{"full_name": "minh-tg/specht"}},
		},
	}))

	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=my-app", "-tool=trivy"}, strings.NewReader(`{}`), &stdout, &stderr, nil)
	require.Equal(t, 2, code)
	assert.Contains(t, stderr.String(), "API_KEY environment variable is required")
	assert.Contains(t, stderr.String(), "SPECHT_API_KEY")
}

func TestRun_MissingAPIKeyOnPushEventFails(t *testing.T) {
	clearCIMarkers(t)
	clearAPIKeyEnv(t)
	t.Setenv("GITHUB_EVENT_NAME", "push")
	t.Setenv("GITHUB_EVENT_PATH", "")
	t.Setenv("API_URL", "https://specht.example.com")

	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=my-app", "-tool=trivy"}, strings.NewReader(`{}`), &stdout, &stderr, nil)
	require.Equal(t, 2, code)
	assert.Contains(t, stderr.String(), "API_KEY environment variable is required")
}

func TestRun_AcceptsSpechtAPIKeyAlias(t *testing.T) {
	srv := newChangeLinkServer(t, "rep-alias", false)
	defer srv.Close()
	clearCIMarkers(t)
	clearAPIKeyEnv(t)
	t.Setenv("SPECHT_API_KEY", "test-key")
	t.Setenv("API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=my-app", "-tool=trivy"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, srv.Client())
	require.Equal(t, 0, code, "stderr:\n%s", stderr.String())
}

func TestIsForkPullRequest(t *testing.T) {
	forkEvent := map[string]any{
		"pull_request": map[string]any{
			"head": map[string]any{"repo": map[string]any{"fork": true, "full_name": "contributor/specht"}},
			"base": map[string]any{"repo": map[string]any{"full_name": "minh-tg/specht"}},
		},
	}
	inRepoEvent := map[string]any{
		"pull_request": map[string]any{
			"head": map[string]any{"repo": map[string]any{"fork": false, "full_name": "minh-tg/specht"}},
			"base": map[string]any{"repo": map[string]any{"full_name": "minh-tg/specht"}},
		},
	}

	tests := []struct {
		name      string
		eventName string
		payload   any
		noPath    bool
		want      bool
	}{
		{name: "fork flag", eventName: "pull_request", payload: forkEvent, want: true},
		{name: "same repo branch", eventName: "pull_request", payload: inRepoEvent, want: false},
		{name: "push event", eventName: "push", payload: forkEvent, want: false},
		{name: "missing event name", eventName: "", payload: forkEvent, want: false},
		{name: "missing payload path", eventName: "pull_request", noPath: true, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GITHUB_EVENT_NAME", tt.eventName)
			if tt.noPath {
				t.Setenv("GITHUB_EVENT_PATH", filepath.Join(t.TempDir(), "absent.json"))
			} else {
				t.Setenv("GITHUB_EVENT_PATH", writeEventPayload(t, tt.payload))
			}
			assert.Equal(t, tt.want, isForkPullRequest())
		})
	}
}

func TestRun_ExcludeTool(t *testing.T) {
	t.Setenv("API_KEY", "dummy")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=test", "-tool=trivy", "-exclude-tool=trivy"}, strings.NewReader(`{}`), &stdout, &stderr, nil)
	assert.Equal(t, 0, code)
	assert.Contains(t, stderr.String(), `skipped: scanner "trivy" excluded`)
}

func TestRun_IntroducedOnly_Pass(t *testing.T) {
	t.Setenv("API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			writeTestJSONResponse(t, w, client.IngestResponse{
				ReportID:          "rep-pass",
				TotalFindings:     10,
				IntroducedCount:   0,
				PreExistingCount:  10,
				ThresholdBreached: false,
			})
		case "/api/v1/projects/my-app/pr-check":
			writeTestJSONResponse(t, w, client.PRCheckPreview{
				Conclusion:  "success",
				Title:       "Specht Gate: 0 blocking findings",
				Summary:     "No new vulnerabilities introduced.",
				Annotations: []client.PRCheckAnnotation{},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	args := []string{
		"-file=../../internal/parser/trivy/testdata/alpine-scan.json",
		"-project=my-app",
		"-tool=trivy",
		"-base-ref=main",
		"-commit=abc12345",
		"-branch=feat/add-dep",
	}
	code := run(args, bytes.NewReader(nil), &stdout, &stderr, srv.Client())
	assert.Equal(t, 0, code)
	assert.Contains(t, stderr.String(), "✅ SPECHT SECURITY GATE: PASSED")
	assert.Contains(t, stderr.String(), "PRE-EXISTING DEBT IN BASELINE: 10 findings ignored")
}

func TestRunWithContextCancelsAPIRequest(t *testing.T) {
	clearCIEnvironment(t)
	t.Setenv("API_KEY", "test-key")
	t.Setenv("API_URL", "http://test")
	requestStarted := make(chan struct{})
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		close(requestStarted)
		<-req.Context().Done()
		return nil, req.Context().Err()
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		hc := &http.Client{Transport: transport}
		done <- runWithContext(ctx, []string{"-project=my-app", "-tool=trivy"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, hc)
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("API request did not start")
	}
	cancel()
	select {
	case code := <-done:
		assert.Equal(t, 2, code)
		assert.Contains(t, stderr.String(), "context canceled")
	case <-time.After(time.Second):
		t.Fatal("adapter did not stop after context cancellation")
	}
}

func TestRun_IntroducedOnly_PreviewFailureWarnsWithoutChangingVerdict(t *testing.T) {
	stubRetrySleep(t)
	t.Setenv("API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			writeTestJSONResponse(t, w, client.IngestResponse{
				ReportID:          "rep-pass",
				ThresholdBreached: false,
			})
		case "/api/v1/projects/my-app/pr-check":
			http.Error(w, "preview temporarily unavailable", http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	args := []string{
		"-project=my-app",
		"-tool=trivy",
		"-base-ref=main",
		"-commit=abc12345",
	}
	code := run(args, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, srv.Client())
	assert.Equal(t, 0, code)
	assert.Contains(t, stderr.String(), "could not fetch PR check preview")
	assert.Contains(t, stderr.String(), "✅ SPECHT SECURITY GATE: PASSED")
}

func TestRun_IntroducedOnly_Fail_WithAnnotations_And_Summary(t *testing.T) {
	t.Setenv("API_KEY", "test-key")

	tmpSummary, err := os.CreateTemp("", "github_step_summary_*.md")
	require.NoError(t, err)
	summaryPath := tmpSummary.Name()
	t.Cleanup(func() {
		if err := os.Remove(summaryPath); err != nil {
			t.Errorf("remove temporary summary file: %v", err)
		}
	})
	require.NoError(t, tmpSummary.Close())

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			writeTestJSONResponse(t, w, client.IngestResponse{
				ReportID:          "rep-fail",
				TotalFindings:     5,
				IntroducedCount:   1,
				PreExistingCount:  4,
				ThresholdBreached: true,
			})
		case "/api/v1/projects/my-app/pr-check":
			writeTestJSONResponse(t, w, client.PRCheckPreview{
				Conclusion: "failure",
				Title:      "Specht Gate: 1 blocking finding",
				Summary:    "### Vulnerability Report\n- CVE-2023-45853 in zlib",
				Annotations: []client.PRCheckAnnotation{
					{
						File:      "go.mod",
						StartLine: 34,
						EndLine:   34,
						Level:     "error",
						Title:     "CVE-2023-45853",
						Message:   "Critical buffer overflow in zlib",
					},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	t.Setenv("API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	args := []string{
		"-file=../../internal/parser/trivy/testdata/alpine-scan.json",
		"-project=my-app",
		"-tool=trivy",
		"-base-ref=main",
		"-commit=abc12345",
		"-annotations=true",
		"-summary-file=" + tmpSummary.Name(),
	}
	code := run(args, bytes.NewReader(nil), &stdout, &stderr, srv.Client())
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr.String(), "❌ SPECHT SECURITY GATE: FAILED")
	assert.Contains(t, stderr.String(), "🚨 NEW BLOCKING FINDINGS INTRODUCED IN THIS CHANGE (1):")
	assert.Contains(t, stderr.String(), "• [ERROR] CVE-2023-45853: go.mod:34")
	assert.Contains(t, stderr.String(), "::error file=go.mod,line=34,endLine=34,title=CVE-2023-45853::Critical buffer overflow in zlib")

	// Verify summary file content
	summaryBytes, err := os.ReadFile(tmpSummary.Name())
	require.NoError(t, err)
	assert.Contains(t, string(summaryBytes), "### Vulnerability Report")
	assert.Contains(t, string(summaryBytes), "CVE-2023-45853 in zlib")
	assert.Contains(t, string(summaryBytes), "[View this change in Specht]("+srv.URL+"/my-app/changes/abc12345)")
}

func TestRun_BaselinePolicy_Warn_And_Fail(t *testing.T) {
	t.Setenv("API_KEY", "test-key")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeTestJSONResponse(t, w, client.IngestResponse{
			ReportID:          "rep-fallback",
			TotalFindings:     2,
			ThresholdBreached: false,
			FallbackReason:    "no baseline report found for branch 'main'",
		})
	}))
	defer srv.Close()
	t.Setenv("API_URL", srv.URL)

	// Case 1: warn policy (default) -> exit 0
	{
		var stdout, stderr bytes.Buffer
		code := run([]string{
			"-file=../../internal/parser/trivy/testdata/alpine-scan.json",
			"-project=my-app",
			"-tool=trivy",
			"-base-ref=main",
			"-baseline-policy=warn",
		}, bytes.NewReader(nil), &stdout, &stderr, srv.Client())
		assert.Equal(t, 0, code)
		assert.Contains(t, stderr.String(), "⚠️  BASELINE WARNING: no baseline report found for branch 'main'")
	}

	// Case 2: fail policy -> exit 1
	{
		var stdout, stderr bytes.Buffer
		code := run([]string{
			"-file=../../internal/parser/trivy/testdata/alpine-scan.json",
			"-project=my-app",
			"-tool=trivy",
			"-base-ref=main",
			"-baseline-policy=fail",
		}, bytes.NewReader(nil), &stdout, &stderr, srv.Client())
		assert.Equal(t, 1, code)
		assert.Contains(t, stderr.String(), "gate FAILED: missing baseline under baseline-policy=fail")
	}
}

func TestPublishGitHubCheckRun(t *testing.T) {
	preview := &client.PRCheckPreview{
		Conclusion: "failure",
		Title:      "Specht Gate: 1 blocking finding",
		Summary:    "Summary markdown",
		Annotations: []client.PRCheckAnnotation{
			{
				File:      "src/main.go",
				StartLine: 10,
				EndLine:   12,
				Level:     "error",
				Title:     "SQL Injection",
				Message:   "Unsanitized input query",
			},
		},
	}

	t.Run("includes details_url and summary link", func(t *testing.T) {
		var capturedReq gitHubCheckRunRequest
		var rawBody []byte
		var authHeader string

		ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "POST", r.Method)
			assert.Equal(t, "/repos/owner/repo/check-runs", r.URL.Path)
			authHeader = r.Header.Get("Authorization")
			var err error
			rawBody, err = io.ReadAll(r.Body)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(rawBody, &capturedReq))

			w.WriteHeader(http.StatusCreated)
			if _, err := w.Write([]byte(`{"id": 12345}`)); err != nil {
				t.Errorf("write check-run response: %v", err)
			}
		}))
		defer ghSrv.Close()

		changeLink := "https://specht.example.com/my-app/changes/sha123"
		err := publishGitHubCheckRun(context.Background(), githubCheckRunClient(ghSrv), "secret-token", "owner/repo", "sha123", changeLink, preview)
		require.NoError(t, err)
		assert.Equal(t, "Bearer secret-token", authHeader)
		assert.Equal(t, "Specht Security Gate", capturedReq.Name)
		assert.Equal(t, "sha123", capturedReq.HeadSHA)
		assert.Equal(t, "failure", capturedReq.Conclusion)
		assert.Equal(t, changeLink, capturedReq.DetailsURL)
		assert.Contains(t, string(rawBody), `"details_url":"`+changeLink+`"`)
		assert.Len(t, capturedReq.Output.Annotations, 1)
		assert.Equal(t, "src/main.go", capturedReq.Output.Annotations[0].Path)
		assert.Equal(t, "failure", capturedReq.Output.Annotations[0].AnnotationLevel)
		assert.Equal(t, "Summary markdown\n\n[View this change in Specht]("+changeLink+")", capturedReq.Output.Summary)
	})

	t.Run("omits details_url without a change link", func(t *testing.T) {
		var capturedReq gitHubCheckRunRequest
		var rawBody []byte

		ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var err error
			rawBody, err = io.ReadAll(r.Body)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(rawBody, &capturedReq))
			w.WriteHeader(http.StatusCreated)
		}))
		defer ghSrv.Close()

		changeLink := changeURL("https://specht.example.com", "", "sha123")
		require.Empty(t, changeLink)
		err := publishGitHubCheckRun(context.Background(), githubCheckRunClient(ghSrv), "secret-token", "owner/repo", "sha123", changeLink, preview)
		require.NoError(t, err)
		assert.NotContains(t, string(rawBody), "details_url")
		assert.Equal(t, "Summary markdown", capturedReq.Output.Summary)
		assert.NotContains(t, capturedReq.Output.Summary, "View this change in Specht")
	})
}

func TestPublishGitHubCheckRun_BoundsTheErrorBodyItEchoes(t *testing.T) {
	ghSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(strings.Repeat("x", 4<<20)))
	}))
	defer ghSrv.Close()
	preview := &client.PRCheckPreview{Conclusion: "success", Title: "t", Summary: "s"}

	err := publishGitHubCheckRun(context.Background(), githubCheckRunClient(ghSrv), "tok", "owner/repo", "sha123", "", preview)

	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 502")
	assert.Less(t, len(err.Error()), 2*maxGitHubErrorBytes, "a hostile or broken API must not put megabytes in our logs")
}

func TestGitHubClientOrDefault_NeverHangsForever(t *testing.T) {
	assert.Positive(t, gitHubClientOrDefault(nil).Timeout, "the default client has a request timeout")

	custom := &http.Client{}
	assert.Same(t, custom, gitHubClientOrDefault(custom), "an injected client is used as given")
}

func githubCheckRunClient(ghSrv *httptest.Server) *http.Client {
	return &http.Client{
		Transport: roundTripperFunc(func(req *http.Request) (*http.Response, error) {
			if strings.HasPrefix(req.URL.String(), "https://api.github.com/") {
				req.URL.Scheme = "http"
				req.URL.Host = ghSrv.Listener.Addr().String()
			}
			return http.DefaultTransport.RoundTrip(req)
		}),
	}
}

func TestChangeURLWithReport(t *testing.T) {
	base := "https://specht.example.com"
	assert.Equal(t, base+"/my-app/changes/abc", changeURLWithReport(base, "my-app", "abc", ""))
	assert.Equal(t, base+"/my-app/changes/abc?report=rep-1", changeURLWithReport(base, "my-app", "abc", "rep-1"))
	assert.Equal(t, base+"/my-app/changes/abc?report=a%26b", changeURLWithReport(base, "my-app", "abc", "a&b"))
	assert.Empty(t, changeURLWithReport(base, "", "abc", "rep-1"), "a missing project omits the link")
	assert.Empty(t, changeURLWithReport(base, "my-app", "", "rep-1"), "a missing commit omits the link")
}

func TestRun_PrintsChangeLinkOnStdout(t *testing.T) {
	t.Run("pass with report id", func(t *testing.T) {
		srv := newChangeLinkServer(t, "rep-link", false)
		defer srv.Close()
		t.Setenv("API_KEY", "test-key")
		t.Setenv("API_URL", srv.URL)

		var stdout, stderr bytes.Buffer
		code := run([]string{"-project=my-app", "-tool=trivy", "-commit=abc12345", "-branch=feat/x"},
			strings.NewReader(`{"Results":[]}`), &stdout, &stderr, srv.Client())
		require.Equal(t, 0, code, "stderr:\n%s", stderr.String())
		assert.Contains(t, stdout.String(), "View this change in Specht: "+srv.URL+"/my-app/changes/abc12345?report=rep-link")
	})

	t.Run("blocked without report id", func(t *testing.T) {
		srv := newChangeLinkServer(t, "", true)
		defer srv.Close()
		t.Setenv("API_KEY", "test-key")
		t.Setenv("API_URL", srv.URL)

		var stdout, stderr bytes.Buffer
		code := run([]string{"-project=my-app", "-tool=trivy", "-commit=abc12345"},
			strings.NewReader(`{"Results":[]}`), &stdout, &stderr, srv.Client())
		require.Equal(t, 1, code, "stderr:\n%s", stderr.String())
		assert.Contains(t, stdout.String(), "View this change in Specht: "+srv.URL+"/my-app/changes/abc12345")
		assert.NotContains(t, stdout.String(), "?report=", "an unknown report id must not add a query")
	})

	t.Run("no commit omits the link", func(t *testing.T) {
		srv := newChangeLinkServer(t, "rep-link", false)
		defer srv.Close()
		t.Setenv("API_KEY", "test-key")
		t.Setenv("API_URL", srv.URL)

		var stdout, stderr bytes.Buffer
		code := run([]string{"-project=my-app", "-tool=trivy"},
			strings.NewReader(`{"Results":[]}`), &stdout, &stderr, srv.Client())
		require.Equal(t, 0, code, "stderr:\n%s", stderr.String())
		assert.NotContains(t, stdout.String(), "View this change in Specht")
	})
}

// newChangeLinkServer serves the ingest, preview and gate calls one adapter
// run makes, with a controllable report id and gate verdict.
func newChangeLinkServer(t *testing.T, reportID string, breached bool) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			writeTestJSONResponse(t, w, client.IngestResponse{ReportID: reportID, TotalFindings: 1, ThresholdBreached: breached})
		case "/api/v1/projects/my-app/pr-check":
			writeTestJSONResponse(t, w, client.PRCheckPreview{Conclusion: "success", Title: "t", Summary: "s"})
		case "/api/v1/projects/my-app/gate":
			writeTestJSONResponse(t, w, client.GateStatus{ThresholdBreached: breached, BlockingCount: 1})
		default:
			http.NotFound(w, r)
		}
	}))
}

func stubRetrySleep(t *testing.T) *[]time.Duration {
	t.Helper()
	slept := &[]time.Duration{}
	prev := adapterSleep
	adapterSleep = func(_ context.Context, d time.Duration) { *slept = append(*slept, d) }
	t.Cleanup(func() { adapterSleep = prev })
	return slept
}

func TestRun_RetriesTransientIngestFailure(t *testing.T) {
	slept := stubRetrySleep(t)
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			attempts++
			if attempts == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			writeTestJSONResponse(t, w, client.IngestResponse{ReportID: "rep-retry"})
		case "/api/v1/projects/my-app/gate":
			writeTestJSONResponse(t, w, client.GateStatus{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	clearCIMarkers(t)
	t.Setenv("API_KEY", "test-key")
	t.Setenv("API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=my-app", "-tool=trivy"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, srv.Client())
	require.Equal(t, 0, code, "stderr:\n%s", stderr.String())
	assert.Equal(t, 2, attempts, "the 503 is retried once")
	assert.Equal(t, []time.Duration{time.Second}, *slept)
}

func TestRun_GivesUpAfterTwoRetries(t *testing.T) {
	slept := stubRetrySleep(t)
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	clearCIMarkers(t)
	t.Setenv("API_KEY", "test-key")
	t.Setenv("API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=my-app", "-tool=trivy"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, srv.Client())
	require.Equal(t, 2, code)
	assert.Equal(t, 3, attempts, "the initial attempt plus two retries")
	assert.Equal(t, []time.Duration{time.Second, 3 * time.Second}, *slept)
	assert.Contains(t, stderr.String(), "ingest failed")
}

func TestRun_DoesNotRetryBadRequest(t *testing.T) {
	slept := stubRetrySleep(t)
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()
	clearCIMarkers(t)
	t.Setenv("API_KEY", "test-key")
	t.Setenv("API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=my-app", "-tool=trivy"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, srv.Client())
	require.Equal(t, 2, code)
	assert.Equal(t, 1, attempts, "a 400 is not transient")
	assert.Empty(t, *slept)
}

func TestRun_HonoursRetryAfterOn429(t *testing.T) {
	slept := stubRetrySleep(t)
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/reports":
			attempts++
			if attempts == 1 {
				w.Header().Set("Retry-After", "2")
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			writeTestJSONResponse(t, w, client.IngestResponse{ReportID: "rep-429"})
		case "/api/v1/projects/my-app/gate":
			writeTestJSONResponse(t, w, client.GateStatus{})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	clearCIMarkers(t)
	t.Setenv("API_KEY", "test-key")
	t.Setenv("API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=my-app", "-tool=trivy"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, srv.Client())
	require.Equal(t, 0, code, "stderr:\n%s", stderr.String())
	assert.Equal(t, []time.Duration{2 * time.Second}, *slept, "Retry-After replaces the default backoff")
}

func TestRun_DuplicateReportMessage(t *testing.T) {
	slept := stubRetrySleep(t)
	var attempts int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusConflict)
		writeTestJSONResponse(t, w, map[string]any{
			"error": map[string]string{"code": "duplicate_report", "message": "report already exists for this project and data"},
		})
	}))
	defer srv.Close()
	clearCIMarkers(t)
	t.Setenv("API_KEY", "test-key")
	t.Setenv("API_URL", srv.URL)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=my-app", "-tool=trivy"}, strings.NewReader(`{"Results":[]}`), &stdout, &stderr, srv.Client())
	require.Equal(t, 2, code)
	assert.Equal(t, 1, attempts, "a 409 duplicate is not retried")
	assert.Empty(t, *slept)
	assert.Contains(t, stderr.String(), "duplicate report")
	assert.Contains(t, stderr.String(), "already ingested")
}

func TestRetryAfterDelay(t *testing.T) {
	assert.Equal(t, 2*time.Second, retryAfterDelay("2"))
	assert.Equal(t, 30*time.Second, retryAfterDelay("600"), "Retry-After is capped")
	assert.Zero(t, retryAfterDelay(""))
	assert.Zero(t, retryAfterDelay("0"))
	assert.Zero(t, retryAfterDelay("not-a-date"))
}

func TestRetryTransportRetriesNetworkErrors(t *testing.T) {
	var calls int
	base := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		if calls < 3 {
			return nil, io.EOF
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	var slept []time.Duration
	rt := &retryTransport{base: base, sleep: func(_ context.Context, d time.Duration) { slept = append(slept, d) }}
	req, err := http.NewRequest(http.MethodGet, "http://example.test/x", nil)
	require.NoError(t, err)

	resp, err := rt.RoundTrip(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	assert.Equal(t, 3, calls)
	assert.Equal(t, []time.Duration{time.Second, 3 * time.Second}, slept)
}

func TestRetryTransportStopsOnContextCancelDuringBackoff(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var calls int
	base := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{
			StatusCode: http.StatusServiceUnavailable,
			Body:       io.NopCloser(strings.NewReader("")),
			Header:     make(http.Header),
			Request:    req,
		}, nil
	})
	rt := &retryTransport{base: base, sleep: func(_ context.Context, _ time.Duration) { cancel() }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://example.test/x", nil)
	require.NoError(t, err)

	_, err = rt.RoundTrip(req)
	require.ErrorIs(t, err, context.Canceled)
	assert.Equal(t, 1, calls, "shutdown must stop further attempts")
}

func TestChangeURL(t *testing.T) {
	tests := []struct {
		name    string
		apiURL  string
		project string
		commit  string
		want    string
	}{
		{
			name:    "builds the change page link",
			apiURL:  "https://specht.example.com",
			project: "my-app",
			commit:  "abc12345",
			want:    "https://specht.example.com/my-app/changes/abc12345",
		},
		{
			name:    "trailing slash on apiURL does not double up",
			apiURL:  "https://specht.example.com/",
			project: "my-app",
			commit:  "abc12345",
			want:    "https://specht.example.com/my-app/changes/abc12345",
		},
		{
			name:    "escapes a hostile project slug",
			apiURL:  "https://specht.example.com",
			project: "a b)(c",
			commit:  "abc12345",
			want:    "https://specht.example.com/a%20b%29%28c/changes/abc12345",
		},
		{
			name:    "escapes a hostile commit sha",
			apiURL:  "https://specht.example.com",
			project: "my-app",
			commit:  "a b)(c",
			want:    "https://specht.example.com/my-app/changes/a%20b%29%28c",
		},
		{name: "empty apiURL", apiURL: "", project: "my-app", commit: "abc12345", want: ""},
		{name: "empty project", apiURL: "https://specht.example.com", project: "", commit: "abc12345", want: ""},
		{name: "empty commit", apiURL: "https://specht.example.com", project: "my-app", commit: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := changeURL(tt.apiURL, tt.project, tt.commit)
			assert.Equal(t, tt.want, got)
			if tt.project == "a b)(c" || tt.commit == "a b)(c" {
				assert.NotContains(t, got, " ")
				assert.NotContains(t, got, "(")
				assert.NotContains(t, got, ")")
			}
		})
	}
}

func TestWithChangeLink(t *testing.T) {
	link := "https://specht.example.com/my-app/changes/abc12345"
	assert.Equal(t, "Summary\n\n[View this change in Specht]("+link+")", withChangeLink("Summary", link))
	assert.Equal(t, "Summary\n\n[View this change in Specht]("+link+")", withChangeLink("Summary\n", link))
	assert.Equal(t, "[View this change in Specht]("+link+")", withChangeLink("", link))
	assert.Equal(t, "Summary", withChangeLink("Summary", ""))
}

type roundTripperFunc func(req *http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestEscapeWorkflowCommand(t *testing.T) {
	assert.Equal(t, "foo%25bar%3Abaz%2Cqux%0Aline", escapeCommandProperty("foo%bar:baz,qux\nline"))
	assert.Equal(t, "foo%25bar%0Aline", escapeCommandData("foo%bar\nline"))
}
