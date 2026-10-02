package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
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

func TestRun_Help(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-help"}, bytes.NewReader(nil), &stdout, &stderr, nil)
	assert.Equal(t, 0, code)
	assert.Contains(t, stderr.String(), "Usage: specht-adapter")
}

func TestRun_MissingAPIKey(t *testing.T) {
	t.Setenv("API_KEY", "")
	var stdout, stderr bytes.Buffer
	code := run([]string{"-project=test", "-tool=trivy"}, strings.NewReader(`{}`), &stdout, &stderr, nil)
	assert.Equal(t, 2, code)
	assert.Contains(t, stderr.String(), "API_KEY environment variable is required")
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
