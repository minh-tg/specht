package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/client"
	"github.com/stretchr/testify/require"
)

func TestRun_PublishedVerdictAndLinksUseSelectedGate(t *testing.T) {
	for _, introduced := range []bool{false, true} {
		name, want, exit := "project", "failure", 1
		if introduced {
			name, want, exit = "introduced", "success", 0
		}
		t.Run(name, func(t *testing.T) {
			clearCIEnvironment(t)
			t.Setenv("API_KEY", "test-key")
			var published struct {
				Conclusion string `json:"conclusion"`
				DetailsURL string `json:"details_url"`
			}
			github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				require.NoError(t, json.NewDecoder(r.Body).Decode(&published))
				w.WriteHeader(http.StatusCreated)
			}))
			defer github.Close()
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/reports":
					writeTestJSONResponse(t, w, client.IngestResponse{ReportID: "exact-report", PreExistingCount: 1})
				case "/api/v1/projects/demo/gate":
					require.Equal(t, "medium", r.URL.Query().Get("severity"))
					writeTestJSONResponse(t, w, client.GateStatus{ThresholdBreached: true, BlockingCount: 1})
				case "/api/v1/projects/demo/pr-check":
					writeTestJSONResponse(t, w, client.PRCheckPreview{ReportID: "exact-report", Conclusion: "success", Summary: "No introduced blockers."})
				default:
					http.NotFound(w, r)
				}
			}))
			defer api.Close()
			t.Setenv("API_URL", api.URL)
			summaryPath := filepath.Join(t.TempDir(), "summary.md")
			args := []string{
				"-tool=sarif", "-project=demo", "-commit=abcdef123", "-severity=medium",
				"-publish-check", "-github-token=test-token", "-github-repo=owner/repo", "-summary-file=" + summaryPath,
			}
			if introduced {
				args = append(args, "-introduced-only")
			}
			var stdout, stderr bytes.Buffer
			code := run(args, strings.NewReader(`{"version":"2.1.0","runs":[]}`), &stdout, &stderr, githubCheckRunClient(github))
			require.Equal(t, exit, code, "%s", stderr.String())
			require.Equal(t, want, published.Conclusion)
			link, err := url.Parse(published.DetailsURL)
			require.NoError(t, err)
			require.Equal(t, "exact-report", link.Query().Get("report"))
			require.Equal(t, name, link.Query().Get("scope"))
			require.Equal(t, "medium", link.Query().Get("severity"))
			require.Contains(t, stdout.String(), published.DetailsURL)
			summary, err := os.ReadFile(summaryPath)
			require.NoError(t, err)
			require.Contains(t, string(summary), published.DetailsURL)
		})
	}
}
