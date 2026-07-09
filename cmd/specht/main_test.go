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
		{"gate check", []string{"specht", "gate", "check", "--project", "my-app"}, command{cmd: cmdGateCheck, project: "my-app"}, ""},
		{"gate check with severity", []string{"specht", "gate", "check", "--project", "my-app", "--severity", "critical"}, command{cmd: cmdGateCheck, project: "my-app", severity: "critical"}, ""},
		{"findings list with filters", []string{"specht", "findings", "list", "--project", "my-app", "--severity", "high,critical", "--status", "open", "--limit", "20"}, command{cmd: cmdFindingsList, project: "my-app", severity: "high,critical", status: "open", limit: 20}, ""},
		{"no command", []string{"specht"}, command{cmd: cmdHelp}, ""},
		{"unknown command", []string{"specht", "unknown"}, command{}, "unknown command: unknown"},
		{"missing subcommand", []string{"specht", "projects"}, command{}, "missing subcommand for projects"},
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
		})
	}
}
