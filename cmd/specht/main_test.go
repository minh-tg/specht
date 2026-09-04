package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/client"
)

func testServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/projects", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{{"slug": "my-app", "name": "My App"}})
	})
	mux.HandleFunc("GET /api/v1/projects/{slug}", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"slug": r.PathValue("slug"), "name": "My App"})
	})
	mux.HandleFunc("GET /api/v1/projects/{slug}/findings", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"id": "f1", "current_title": "Vuln 1", "current_severity": "high", "analysis_state": "unanalyzed", "gate_effect": "block"},
		})
	})
	mux.HandleFunc("GET /api/v1/findings/{id}", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"id": r.PathValue("id"), "current_title": "Vuln 1", "current_severity": "high",
		})
	})
	mux.HandleFunc("GET /api/v1/projects/{slug}/gate", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"threshold_breached": true, "blocking_count": 2,
		})
	})
	mux.HandleFunc("GET /api/v1/projects/{slug}/stats", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"total_findings": 42, "blocking_count": 3, "waiver_count": 5, "report_count": 10,
			"by_severity": []map[string]any{
				{"severity": "critical", "count": 2, "blocking_count": 2},
				{"severity": "high", "count": 10, "blocking_count": 1},
			},
		})
	})
	return httptest.NewServer(mux)
}

func TestCLI_ProjectsList(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	cl := client.New(srv.URL, client.WithToken("test-key"))
	projects, err := cl.ListProjects()
	require.NoError(t, err)
	assert.Len(t, projects, 1)
}

func TestCLI_StatsShow(t *testing.T) {
	srv := testServer()
	defer srv.Close()

	cl := client.New(srv.URL, client.WithToken("test-key"))
	stats, err := cl.GetProjectStats("my-app")
	require.NoError(t, err)
	assert.Equal(t, int32(42), stats.TotalFindings)
	assert.Equal(t, int32(3), stats.BlockingCount)
	assert.Len(t, stats.BySeverity, 2)
}

func TestCLI_ParseArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want command
		err  string
	}{
		{"projects list", []string{"specht", "projects", "list"}, command{cmd: cmdProjectsList}, ""},
		{"projects get", []string{"specht", "projects", "get", "my-app"}, command{cmd: cmdProjectsGet, slug: "my-app"}, ""},
		{"findings list", []string{"specht", "findings", "list", "--project", "my-app"}, command{cmd: cmdFindingsList, project: "my-app"}, ""},
		{"findings get", []string{"specht", "findings", "get", "f1"}, command{cmd: cmdFindingsGet, findingID: "f1"}, ""},
		{"findings reachability list", []string{"specht", "findings", "reachability", "--finding", "f1"}, command{cmd: cmdFindingsReachability, findingID: "f1"}, ""},
		{"findings reachability set", []string{"specht", "findings", "reachability", "--finding", "f1", "--state", "not_reachable", "--evidence", "reviewed"}, command{cmd: cmdFindingsReachability, findingID: "f1", state: "not_reachable", evidence: "reviewed"}, ""},
		{"findings reachability missing finding", []string{"specht", "findings", "reachability"}, command{}, "--finding is required for findings reachability"},
		{"gate check", []string{"specht", "gate", "check", "--project", "my-app"}, command{cmd: cmdGateCheck, project: "my-app"}, ""},
		{"gate check with severity", []string{"specht", "gate", "check", "--project", "my-app", "--severity", "critical"}, command{cmd: cmdGateCheck, project: "my-app", severity: "critical"}, ""},
		{"stats show", []string{"specht", "stats", "show", "my-app"}, command{cmd: cmdStats, slug: "my-app"}, ""},
		{"watcher backfill", []string{"specht", "watcher", "backfill"}, command{cmd: cmdWatcherBackfill}, ""},
		{"watcher status", []string{"specht", "watcher", "status"}, command{cmd: cmdWatcherStatus}, ""},
		{"watcher backfill with since and dry-run", []string{"specht", "watcher", "backfill", "--since", "2026-01-01T00:00:00Z", "--dry-run"}, command{cmd: cmdWatcherBackfill, since: "2026-01-01T00:00:00Z", dryRun: true}, ""},
		{"findings list with filters", []string{"specht", "findings", "list", "--project", "my-app", "--severity", "high,critical", "--status", "open", "--limit", "20"}, command{cmd: cmdFindingsList, project: "my-app", severity: "high,critical", status: "open", limit: 20}, ""},
		{"no command", []string{"specht"}, command{cmd: cmdHelp}, ""},
		{"unknown command", []string{"specht", "unknown"}, command{}, "unknown command: unknown"},
		{"missing subcommand", []string{"specht", "projects"}, command{}, "missing subcommand for projects"},
		{"unknown watcher subcommand", []string{"specht", "watcher", "bogus"}, command{}, "unknown watcher subcommand: bogus"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseArgs(tt.args)
			if tt.err != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want.cmd, got.cmd)
			assert.Equal(t, tt.want.project, got.project)
			assert.Equal(t, tt.want.findingID, got.findingID)
			assert.Equal(t, tt.want.severity, got.severity)
			assert.Equal(t, tt.want.status, got.status)
			assert.Equal(t, tt.want.limit, got.limit)
			assert.Equal(t, tt.want.slug, got.slug)
			assert.Equal(t, tt.want.since, got.since)
			assert.Equal(t, tt.want.dryRun, got.dryRun)
		})
	}
}
