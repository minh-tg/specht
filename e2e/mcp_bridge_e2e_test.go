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

// The MCP bridge spawned as a real process against the live E2E
// server, speaking stdio JSON-RPC — the wire mocks cannot see.

// connectMCPWithKey spawns the bridge with the given credential and extra
// environment, so a test can pin exactly what a real key sees on the wire.
func connectMCPWithKey(t *testing.T, key string, extraEnv ...string) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "specht-e2e-client", Version: "0.0.0"}, nil)
	cmd := exec.Command(mcpBin)
	cmd.Env = cleanEnv(append([]string{"API_URL=" + baseURL, "API_KEY=" + key}, extraEnv...)...)
	session, err := client.Connect(context.Background(), &mcp.CommandTransport{Command: cmd}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// connectMCP spawns the bridge with a session token and the mutation tools
// explicitly enabled, so the whole surface is on the wire. Production defaults
// to read-only; the unit tests pin that default.
func connectMCP(t *testing.T) *mcp.ClientSession {
	t.Helper()
	return connectMCPWithKey(t, adminToken, "MCP_ALLOW_MUTATIONS=true")
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

// A project API key is the credential the bridge documents, and the one CI
// workflows hold. Without MCP_ALLOW_MUTATIONS it must expose only tools that
// key can actually call: no state changes, no session-only routes.
func TestE2E_MCPBridgeWithProjectKeyExposesOnlyKeyUsableReadTools(t *testing.T) {
	slug := newProject(t, "mcp-key-surface")
	ingestFixture(t, slug, adminToken, "high-medium.sarif.json")

	session := connectMCPWithKey(t, mintKey(t, slug)) // no mutation opt-in: the production default
	tools, err := session.ListTools(context.Background(), nil)
	require.NoError(t, err)
	names := make([]string, 0, len(tools.Tools))
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
	}
	require.ElementsMatch(t, []string{
		"findings_list", "findings_get", "gate_check", "pr_preview",
		"patch_preview", "notify_preview", "policy_effective",
		"project_teams", "waivers_list", "waivers_get", "waiver_events",
		"projects_list", "project_get", "project_stats", "project_aging", "reports_list",
		"report_get", "environments_list", "targets_list", "artifacts_list", "finding_events",
	}, names)

	// A read tool really works with this credential, not just on paper.
	text, isErr := mcpText(t, session, "findings_list", map[string]any{"project": slug})
	require.False(t, isErr, text)
	require.Contains(t, text, "Found 2 finding(s)")

	// Neither a mutating nor a session-only tool is registered at all.
	for _, name := range []string{"waivers_create", "reachability_set", "admin_status", "teams_list", "findings_triage", "waivers_request", "scanners_list"} {
		_, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name})
		require.Error(t, err, "tool %q must not be advertised to a project key", name)
	}
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
			"waiver_events", "projects_list", "project_get", "project_stats", "project_aging",
			"reports_list", "report_get", "environments_list", "targets_list", "artifacts_list",
			"finding_events", "scanners_list", "findings_triage", "waivers_request",
			"waivers_withdraw",
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

// TestE2E_MCPBridgeReadsAProjectAndDecidesAFinding walks an assistant that looks over a project,
// records a person's decision on a finding, checks the gate and the history, and asks for a
// waiver on the other finding.
func TestE2E_MCPBridgeReadsAProjectAndDecidesAFinding(t *testing.T) {
	slug := newProject(t, "mcp-triage")
	ingestFixture(t, slug, adminToken, "high-medium.sarif.json")
	findings := listScanFindings(t, slug)
	require.Len(t, findings, 2)
	session := connectMCP(t)

	text, isErr := mcpText(t, session, "projects_list", map[string]any{})
	require.False(t, isErr, text)
	require.Contains(t, text, slug)

	text, isErr = mcpText(t, session, "project_stats", map[string]any{"project": slug})
	require.False(t, isErr, text)
	require.Contains(t, text, "2 finding(s)")

	reports := request[[]struct {
		ID string `json:"id"`
	}](t, http.MethodGet, "/api/v1/projects/"+slug+"/reports", adminToken, nil, http.StatusOK)
	require.Len(t, reports, 1)
	text, isErr = mcpText(t, session, "reports_list", map[string]any{"project": slug})
	require.False(t, isErr, text)
	require.Contains(t, text, reports[0].ID)
	text, isErr = mcpText(t, session, "report_get", map[string]any{"report_id": reports[0].ID})
	require.False(t, isErr, text)
	require.Contains(t, text, "Report: "+reports[0].ID)

	for _, tool := range []string{"project_get", "project_aging", "environments_list", "targets_list", "artifacts_list"} {
		text, isErr = mcpText(t, session, tool, map[string]any{"project": slug})
		require.False(t, isErr, "%s: %s", tool, text)
	}

	text, isErr = mcpText(t, session, "scanners_list", map[string]any{})
	require.False(t, isErr, text)
	require.Contains(t, text, "semgrep")

	// The high finding blocks; a decision without a reason is refused, one with a reason lifts it.
	high := highFinding(t, slug).ID
	require.True(t, getGate(t, slug, "").ThresholdBreached)
	_, isErr = mcpText(t, session, "findings_triage", map[string]any{"finding_id": high, "state": "false_positive"})
	require.True(t, isErr, "a decision that ignores the gate needs a reason")

	text, isErr = mcpText(t, session, "findings_triage", map[string]any{"finding_id": high, "state": "false_positive", "reason": "test fixture"})
	require.False(t, isErr, text)
	require.Contains(t, text, "gate: ignore")
	require.False(t, getGate(t, slug, "").ThresholdBreached)

	text, isErr = mcpText(t, session, "finding_events", map[string]any{"finding_id": high})
	require.False(t, isErr, text)
	require.Contains(t, text, "false_positive")
	require.Contains(t, text, "test fixture")

	// A request is not an approval: the waiver stays pending, and the assistant can take it back.
	other := findings[0].ID
	if other == high {
		other = findings[1].ID
	}
	expires := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	text, isErr = mcpText(t, session, "waivers_request", map[string]any{
		"project": slug, "finding_ids": []string{other}, "reason": "no fix upstream", "expires_at": expires,
	})
	require.False(t, isErr, text)
	require.Contains(t, text, "waiting for a decision")

	pending := request[[]waiverDetail](t, http.MethodGet, "/api/v1/projects/"+slug+"/waivers", adminToken, nil, http.StatusOK)
	require.Len(t, pending, 1)
	text, isErr = mcpText(t, session, "waivers_withdraw", map[string]any{"project": slug, "waiver_id": pending[0].ID})
	require.False(t, isErr, text)
	require.Contains(t, text, "withdrawn")
}

// A project key reads the same project data but cannot decide anything, because the decision
// tools are not on offer without the opt-in.
func TestE2E_MCPBridgeProjectKeyReadsButDoesNotDecide(t *testing.T) {
	slug := newProject(t, "mcp-key-reads")
	ingestFixture(t, slug, adminToken, "high.sarif.json")
	session := connectMCPWithKey(t, mintKey(t, slug))

	text, isErr := mcpText(t, session, "project_stats", map[string]any{"project": slug})
	require.False(t, isErr, text)
	require.Contains(t, text, "1 finding(s)")

	text, isErr = mcpText(t, session, "reports_list", map[string]any{"project": slug})
	require.False(t, isErr, text)
	require.Contains(t, text, "sarif")

	_, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "findings_triage", Arguments: map[string]any{"finding_id": "x", "state": "exploitable"}})
	require.Error(t, err)
}
