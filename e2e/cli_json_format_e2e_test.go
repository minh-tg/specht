//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestE2E_CLIDataCommandsHonourJSON runs every command that returns data with --format json and
// requires JSON on standard output. A command that ignored the flag printed its table instead, and
// a script piping it into a JSON reader failed with no hint why.
func TestE2E_CLIDataCommandsHonourJSON(t *testing.T) {
	slug := newProject(t, "cli-json")
	ingestFixture(t, slug, mintKey(t, slug), "high-medium.sarif.json")
	finding := listFindings(t, slug)[0].ID
	person := registerPerson(t, "json-member")
	team := request[struct {
		ID string `json:"id"`
	}](t, http.MethodPost, "/api/v1/teams", adminToken, map[string]string{"name": "json-team-" + randomHex(3)}, http.StatusCreated)
	teamID := team.ID

	soon := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	tests := []struct {
		name string
		args []string
	}{
		{"projects list", []string{"projects", "list"}},
		{"projects get", []string{"projects", "get", slug}},
		{"findings list", []string{"findings", "list", "--project", slug}},
		{"findings get", []string{"findings", "get", finding}},
		{"findings verify", []string{"findings", "verify", finding}},
		{"findings reachability", []string{"findings", "reachability", "--finding", finding, "--state", "unknown"}},
		{"stats show", []string{"stats", "show", slug}},
		{"stats aging", []string{"stats", "aging", slug}},
		{"teams create", []string{"teams", "create", "--name", "json-created-" + randomHex(3)}},
		{"teams list", []string{"teams", "list"}},
		{"teams members", []string{"teams", "members", "--id", teamID}},
		{"teams add", []string{"teams", "add", "--id", teamID, "--user", person.UserID, "--role", "member"}},
		{"project-teams list", []string{"project-teams", "list", "--project", slug}},
		{"policy templates", []string{"policy", "templates"}},
		{"admin status", []string{"admin", "status"}},
		{"watcher status", []string{"watcher", "status"}},
		{"waivers request", []string{"waivers", "request", "--project", slug, "--finding", finding, "--reason", "json test", "--expires", soon}},
		{"waivers create", []string{"waivers", "create", "--project", slug, "--name", "json waiver", "--finding", finding, "--expires", soon}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, exit := cli(t, append([]string{"--format", "json"}, tc.args...)...)
			require.Zero(t, exit, stderr)
			require.Truef(t, json.Valid([]byte(strings.TrimSpace(stdout))), "not JSON: %q", stdout)
		})
	}
}
