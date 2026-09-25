//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// BP-70: the MCP bridge spawned as a real process against the live E2E
// server, speaking stdio JSON-RPC — the wire mocks cannot see.

func connectMCP(t *testing.T) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "specht-e2e-client", Version: "0.0.0"}, nil)
	cmd := exec.Command(mcpBin)
	cmd.Env = cleanEnv("API_URL="+baseURL, "API_KEY="+adminToken)
	session, err := client.Connect(context.Background(), &mcp.CommandTransport{Command: cmd}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// mcpText calls one tool and returns its text plus the error flag; API and
// validation failures must arrive as IsError results, never as panics.
func mcpText(t *testing.T, session *mcp.ClientSession, tool string, args map[string]any) (string, bool) {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      tool,
		Arguments: args,
	})
	require.NoErrorf(t, err, "tool %s must answer", tool)
	require.NotEmptyf(t, result.Content, "tool %s must return content", tool)
	text, ok := result.Content[0].(*mcp.TextContent)
	require.Truef(t, ok, "tool %s returns text content", tool)
	return text.Text, result.IsError
}

func TestE2E_MCPBridgeOverStdio(t *testing.T) {
	slug := newProject(t, "mcp-bridge")
	ingestFixture(t, slug, adminToken, "high-medium.sarif.json")
	findings := listScanFindings(t, slug)
	require.Len(t, findings, 2)

	session := connectMCP(t)

	t.Run("initialize advertises the full toolset", func(t *testing.T) {
		init := session.InitializeResult()
		require.NotNil(t, init)
		require.Equal(t, "specht-mcp", init.ServerInfo.Name)

		tools, err := session.ListTools(context.Background(), nil)
		require.NoError(t, err)
		names := make([]string, 0, len(tools.Tools))
		for _, tool := range tools.Tools {
			names = append(names, tool.Name)
		}
		require.ElementsMatch(t, []string{
			"findings_list", "findings_get", "gate_check", "pr_preview",
			"patch_preview", "notify_preview", "admin_status",
			"admin_retention_preview", "policy_effective", "teams_list",
			"project_teams", "reachability_set", "watcher_status",
			"waivers_list", "waivers_get", "waivers_create", "waivers_toggle",
			"waiver_events",
		}, names)
	})

	t.Run("findings_list renders the live findings", func(t *testing.T) {
		text, isErr := mcpText(t, session, "findings_list", map[string]any{"project": slug})
		require.False(t, isErr, text)
		require.Contains(t, text, "Found 2 finding(s)")
		for _, f := range findings {
			require.Contains(t, text, f.ID)
			require.Contains(t, text, f.CurrentTitle)
		}
	})

	t.Run("gate_check reflects the gate and waivers_create flips it with an expiry", func(t *testing.T) {
		// The high fixture breaches the default floor.
		text, isErr := mcpText(t, session, "gate_check", map[string]any{"project": slug})
		require.False(t, isErr, text)
		require.Contains(t, text, "gate FAILED", text)
		require.Contains(t, text, "blocking finding", text)

		// The bridge creates a time-boxed waiver through the real API.
		createdAt := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
		text, isErr = mcpText(t, session, "waivers_create", map[string]any{
			"project": slug, "name": "mcp-window",
			"finding_ids": []string{findings[0].ID},
			"expires_at":  createdAt,
		})
		require.False(t, isErr, text)
		require.Contains(t, text, "Waiver created:", text)

		// The expiry round-trips: read the waiver back over the API.
		var created waiverDetail
		for _, w := range request[[]waiverDetail](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/waivers", adminToken, nil, http.StatusOK) {
			if w.Name == "mcp-window" {
				created = w
			}
		}
		require.NotEmpty(t, created.ID, "the MCP-created waiver is readable over HTTP")
		require.NotNil(t, created.ExpiresAt, "expires_at reached the API through the bridge")

		// With the waiver active, the same live gate now passes.
		text, isErr = mcpText(t, session, "gate_check", map[string]any{"project": slug})
		require.False(t, isErr, text)
		require.Contains(t, text, "gate PASSED", text)

		// A second waiver without an expiry stays open-ended.
		text, isErr = mcpText(t, session, "waivers_create", map[string]any{
			"project": slug, "name": "mcp-open",
			"finding_ids": []string{findings[1].ID},
		})
		require.False(t, isErr, text)
		require.Contains(t, text, "Waiver created:", text)
		for _, w := range request[[]waiverDetail](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/waivers", adminToken, nil, http.StatusOK) {
			if w.Name == "mcp-open" {
				require.Nil(t, w.ExpiresAt, "absent expires_at stays absent")
			}
		}
	})

	t.Run("API failures surface as tool errors and the session survives", func(t *testing.T) {
		text, isErr := mcpText(t, session, "gate_check", map[string]any{"project": "no-such-project"})
		require.True(t, isErr, "a live404 must be an error result: %s", text)

		text, isErr = mcpText(t, session, "findings_list", map[string]any{})
		require.True(t, isErr, "validation stays an error result: %s", text)

		// The session is still alive after tool errors.
		text, isErr = mcpText(t, session, "findings_list", map[string]any{"project": slug})
		require.False(t, isErr, text)
		require.Contains(t, text, "Found 2 finding(s)")
		require.False(t, strings.Contains(text, "panic"))
	})
}
