package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/xMinhx/specht/internal/client"
)

func connectMCPServer(t *testing.T, api API) *mcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	server := newMCPServer(api)
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
