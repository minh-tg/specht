package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestMCPFindingsGetStripsTerminalControls(t *testing.T) {
	mc := &mockClient{findings: []client.Finding{{
		ID:              "f1",
		CurrentTitle:    "safe\x1b[31m\u202egnihs",
		CurrentSeverity: "high",
	}}}
	session := connectMCPServer(t, mc)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "findings_get",
		Arguments: map[string]any{"finding_id": "f1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %+v", result.Content)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if strings.ContainsAny(text, "\x1b\u202e") {
		t.Fatalf("result still holds terminal controls: %q", text)
	}
	if !strings.Contains(text, "safegnihs") {
		t.Fatalf("result lost the title text: %q", text)
	}
}

func TestMCPReportsListStripsTerminalControls(t *testing.T) {
	tool := "trivy\x1b[2J\u202e-extra"
	mc := &mockClient{reports: []client.Report{{ID: "r1", ToolName: tool, Status: "completed"}}}
	session := connectMCPServer(t, mc)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "reports_list",
		Arguments: map[string]any{"project": "demo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %+v", result.Content)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if strings.ContainsAny(text, "\x1b\u202e") {
		t.Fatalf("result still holds terminal controls: %q", text)
	}
	if !strings.Contains(text, "trivy-extra") {
		t.Fatalf("result lost the tool name: %q", text)
	}
}

// An API error carries server- and scanner-supplied strings, so an error
// result must be stripped the same way as a success result.
func TestMCPErrorResultStripsTerminalControls(t *testing.T) {
	mc := &mockClient{err: errors.New("lookup failed: \x1b[31mred\u202egnihs")}
	session := connectMCPServer(t, mc)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "findings_get",
		Arguments: map[string]any{"finding_id": "f1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatalf("want an error result, got %+v", result.Content)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if strings.ContainsAny(text, "\x1b\u202e") {
		t.Fatalf("error result still holds terminal controls: %q", text)
	}
	if !strings.Contains(text, "redgnihs") {
		t.Fatalf("error result lost the message text: %q", text)
	}
}

// Plain text survives the sanitizer; a scanner-supplied title is quoted.
func TestMCPFindingsListQuotesPlainTitle(t *testing.T) {
	mc := &mockClient{findings: []client.Finding{{
		ID:              "f1",
		CurrentTitle:    "plain title",
		CurrentSeverity: "high",
	}}}
	session := connectMCPServer(t, mc)
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "findings_list",
		Arguments: map[string]any{"project": "demo"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %+v", result.Content)
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if want := "Found 1 finding(s):\n- f1 [high] \"plain title\" (state: , gate: )\n"; text != want {
		t.Fatalf("text = %q, want %q", text, want)
	}
}

func TestMCPArgumentValidationErrorStripsTerminalControls(t *testing.T) {
	session := connectMCPServer(t, &mockClient{})
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "findings_list",
		Arguments: map[string]any{"project": "demo", "limit": "x\x1b[31m‮"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("expected a validation error result")
	}
	text := result.Content[0].(*mcp.TextContent).Text
	if strings.ContainsAny(text, "\x1b‮") {
		t.Fatalf("error result still holds terminal controls: %q", text)
	}
	if !strings.Contains(text, "type: x has type") {
		t.Fatalf("error result lost the argument text: %q", text)
	}
}

func TestMCPUnknownToolErrorStripsTerminalControls(t *testing.T) {
	session := connectMCPServer(t, &mockClient{})
	_, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "nope\x1b[31m‮"})
	if err == nil {
		t.Fatal("expected an unknown tool error")
	}
	if strings.ContainsAny(err.Error(), "\x1b‮") {
		t.Fatalf("error still holds terminal controls: %q", err.Error())
	}
	if !strings.Contains(err.Error(), "unknown tool") {
		t.Fatalf("error lost its meaning: %q", err.Error())
	}
}
