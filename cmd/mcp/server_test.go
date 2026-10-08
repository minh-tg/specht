package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// fullTools registers every tool, for tests about a tool's own behaviour.
var fullTools = toolOptions{AllowMutations: true, SessionCredential: true}

func connectMCPServer(t *testing.T, api API) *mcp.ClientSession {
	t.Helper()
	return connectMCPServerWith(t, api, fullTools)
}

func connectMCPServerWith(t *testing.T, api API, opts toolOptions) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	server := newMCPServer(api, opts)
	client := mcp.NewClient(&mcp.Implementation{Name: "specht-test-client", Version: "0.1.0"}, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})
	return clientSession
}

func TestMCPServerTools(t *testing.T) {
	session := connectMCPServer(t, &mockClient{})
	initialize := session.InitializeResult()
	if initialize == nil {
		t.Fatal("server did not complete initialization")
	}
	if initialize.ServerInfo.Name != "specht-mcp" {
		t.Fatalf("server name = %q, want specht-mcp", initialize.ServerInfo.Name)
	}
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	want := []string{
		"findings_list", "findings_get", "gate_check", "pr_preview",
		"patch_preview", "notify_preview", "admin_status",
		"admin_retention_preview", "policy_effective", "teams_list",
		"project_teams", "reachability_set", "watcher_status", "waivers_list",
		"waivers_get", "waivers_create", "waivers_toggle", "waiver_events",
	}
	got := make(map[string]bool, len(result.Tools))
	for _, tool := range result.Tools {
		got[tool.Name] = true
	}
	for _, name := range want {
		if !got[name] {
			t.Errorf("missing tool %q", name)
		}
	}
	if len(result.Tools) != len(want) {
		t.Fatalf("tool count = %d, want %d", len(result.Tools), len(want))
	}
}

func TestMCPServerSchemasKeepOptionalFieldsOptional(t *testing.T) {
	session := connectMCPServer(t, &mockClient{})
	result, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	wantRequired := map[string]map[string]bool{
		"findings_list":    {"project": true},
		"gate_check":       {"project": true},
		"pr_preview":       {"project": true, "commit": true},
		"notify_preview":   {"finding_id": true, "channel": true, "target": true},
		"reachability_set": {"finding_id": true, "state": true},
		"waivers_create":   {"project": true, "name": true},
	}

	for _, tool := range result.Tools {
		want, ok := wantRequired[tool.Name]
		if !ok {
			continue
		}
		assertRequiredFields(t, tool, want)
	}
}

// assertRequiredFields checks one tool's required list against the want set.
func assertRequiredFields(t *testing.T, tool *mcp.Tool, want map[string]bool) {
	t.Helper()
	schema, ok := tool.InputSchema.(map[string]any)
	if !ok {
		t.Fatalf("%s schema has type %T, want map", tool.Name, tool.InputSchema)
	}
	fields, ok := schema["required"].([]any)
	if !ok {
		t.Fatalf("%s required schema has type %T", tool.Name, schema["required"])
	}
	got := make(map[string]bool, len(fields))
	for _, field := range fields {
		got[field.(string)] = true
	}
	if len(got) != len(want) {
		t.Fatalf("%s required fields = %v, want %v", tool.Name, got, want)
	}
	for field := range want {
		if !got[field] {
			t.Errorf("%s required fields = %v, missing %q", tool.Name, got, field)
		}
	}
}

func TestMCPServerCall(t *testing.T) {
	mc := &mockClient{
		findings: []client.Finding{{ID: "f1", CurrentTitle: "Test Vuln", CurrentSeverity: "high", GateEffect: "block"}},
	}
	session := connectMCPServer(t, mc)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "findings_list",
		Arguments: map[string]any{"project": "my-app"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %+v", result.Content)
	}
	if !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "f1") {
		t.Fatalf("unexpected result: %+v", result.Content)
	}
}

// TestMCPServerWaiversCreateForwardsExpiry pins the tool contract added for
// time-boxed waivers: expires_at reaches the API request, and its absence
// stays absent (omitempty).
func TestMCPServerWaiversCreateForwardsExpiry(t *testing.T) {
	mc := &mockClient{waiver: &client.Waiver{ID: "w1", Name: "release-window"}}
	session := connectMCPServer(t, mc)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "waivers_create",
		Arguments: map[string]any{
			"project": "my-app", "name": "release-window",
			"expires_at": "2030-06-30T12:00:00Z",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %+v", result.Content)
	}
	if mc.waiverReq == nil || mc.waiverReq.ExpiresAt != "2030-06-30T12:00:00Z" {
		t.Fatalf("expires_at not forwarded: %+v", mc.waiverReq)
	}

	// Omitting the field keeps the request free of it (omitempty).
	if _, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "waivers_create",
		Arguments: map[string]any{"project": "my-app", "name": "open-ended"},
	}); err != nil {
		t.Fatal(err)
	}
	if mc.waiverReq == nil || mc.waiverReq.ExpiresAt != "" {
		t.Fatalf("absent expires_at must stay absent: %+v", mc.waiverReq)
	}
}

func TestMCPServerValidation(t *testing.T) {
	session := connectMCPServer(t, &mockClient{})
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "findings_list",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "project") {
		t.Fatalf("unexpected validation error: %+v", result.Content)
	}
}

func TestMCPServerAPIErrorsAreToolErrors(t *testing.T) {
	session := connectMCPServer(t, &mockClient{err: errors.New("api unavailable")})
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "teams_list",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("expected tool error")
	}
	if !strings.Contains(result.Content[0].(*mcp.TextContent).Text, "api unavailable") {
		t.Fatalf("unexpected API error: %+v", result.Content)
	}
}

func listedTools(t *testing.T, opts toolOptions) map[string]bool {
	t.Helper()
	result, err := connectMCPServerWith(t, &mockClient{}, opts).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[string]bool, len(result.Tools))
	for _, tool := range result.Tools {
		got[tool.Name] = true
	}
	return got
}

var (
	readOnlyTools = []string{
		"findings_list", "findings_get", "gate_check", "pr_preview", "patch_preview",
		"notify_preview", "policy_effective", "project_teams", "waivers_list",
		"waivers_get", "waiver_events",
	}
	sessionOnlyTools = []string{"admin_status", "admin_retention_preview", "teams_list", "watcher_status"}
	mutatingTools    = []string{"reachability_set", "waivers_create", "waivers_toggle"}
)

func assertTools(t *testing.T, got map[string]bool, present, absent []string) {
	t.Helper()
	for _, name := range present {
		if !got[name] {
			t.Errorf("tool %q should be registered", name)
		}
	}
	for _, name := range absent {
		if got[name] {
			t.Errorf("tool %q must not be registered", name)
		}
	}
}

// An agent holding a project API key gets read-only tools by default: nothing
// that changes state, and nothing the key cannot call anyway.
func TestMCPServer_DefaultSurfaceIsReadOnlyAndKeyUsable(t *testing.T) {
	got := listedTools(t, toolOptions{})

	assertTools(t, got, readOnlyTools, append(append([]string{}, sessionOnlyTools...), mutatingTools...))
	if len(got) != len(readOnlyTools) {
		t.Errorf("tool count = %d, want %d", len(got), len(readOnlyTools))
	}
}

func TestMCPServer_MutatingToolsNeedAnExplicitOptIn(t *testing.T) {
	got := listedTools(t, toolOptions{AllowMutations: true})

	assertTools(t, got, append(append([]string{}, readOnlyTools...), mutatingTools...), sessionOnlyTools)
}

func TestMCPServer_SessionOnlyToolsNeedASessionCredential(t *testing.T) {
	got := listedTools(t, toolOptions{SessionCredential: true})

	assertTools(t, got, append(append([]string{}, readOnlyTools...), sessionOnlyTools...), mutatingTools)
}

func TestLoadToolOptions(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	tests := []struct {
		name    string
		key     string
		env     map[string]string
		want    toolOptions
		wantErr bool
	}{
		{"project api key, nothing set", "vuln_abc123", nil, toolOptions{}, false},
		{"session token", "eyJhbGciOi.payload.sig", nil, toolOptions{SessionCredential: true}, false},
		{"opt in to mutations", "vuln_abc123", map[string]string{"MCP_ALLOW_MUTATIONS": "true"}, toolOptions{AllowMutations: true}, false},
		{"explicit off", "vuln_abc123", map[string]string{"MCP_ALLOW_MUTATIONS": "false"}, toolOptions{}, false},
		{"typo fails rather than guessing", "vuln_abc123", map[string]string{"MCP_ALLOW_MUTATIONS": "ture"}, toolOptions{}, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := loadToolOptions(tc.key, env(tc.env))

			if (err != nil) != tc.wantErr {
				t.Fatalf("error = %v, wantErr %v", err, tc.wantErr)
			}
			if err == nil && got != tc.want {
				t.Fatalf("options = %+v, want %+v", got, tc.want)
			}
		})
	}
}
