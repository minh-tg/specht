package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"

	"github.com/xMinhx/specht/internal/client"
)

type API interface {
	ListFindings(projectSlug string, severities, states []string, limit, offset int32) ([]client.Finding, error)
	GetFinding(findingID string) (*client.Finding, error)
	GetGateStatus(projectSlug string, severity string) (*client.GateStatus, error)
	ListWaivers(projectSlug string) ([]client.Waiver, error)
	GetWaiver(projectSlug, waiverID string) (*client.WaiverDetail, error)
	CreateWaiver(projectSlug string, req *client.CreateWaiverRequest) (*client.Waiver, error)
	ToggleWaiver(projectSlug, waiverID string) (*client.Waiver, error)
	ListWaiverEvents(projectSlug, waiverID string) ([]client.WaiverEvent, error)
}

type jsonRPCMessage struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      any              `json:"id"`
	Method  string           `json:"method,omitempty"`
	Params  *json.RawMessage `json:"params,omitempty"`
	Result  *json.RawMessage `json:"result,omitempty"`
	Error   *jsonRPCError    `json:"error,omitempty"`
}

type jsonRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type InitResult struct {
	ProtocolVersion string   `json:"protocolVersion"`
	Capabilities    struct{} `json:"capabilities"`
	ServerInfo      struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"serverInfo"`
}

type ToolSpec struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

type ToolListResult struct {
	Tools []ToolSpec `json:"tools"`
}

func parseMessage(data []byte) (jsonRPCMessage, error) {
	var msg jsonRPCMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return msg, err
	}
	return msg, nil
}

func handleMessage(api API, msg jsonRPCMessage) jsonRPCMessage {
	switch msg.Method {
	case "initialize":
		result, _ := json.Marshal(InitResult{
			ProtocolVersion: "2024-11-05",
			ServerInfo: struct {
				Name    string `json:"name"`
				Version string `json:"version"`
			}{Name: "specht-mcp", Version: "0.1.0"},
		})
		raw := json.RawMessage(result)
		return jsonRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: &raw}

	case "tools/list":
		tools := []ToolSpec{
			{
				Name:        "findings_list",
				Description: "List findings for a project",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"project":  map[string]any{"type": "string", "description": "Project slug"},
						"severity": map[string]any{"type": "string", "description": "Comma-separated severity filter (e.g. high,critical)"},
						"status":   map[string]any{"type": "string", "description": "Comma-separated status filter (e.g. open)"},
						"limit":    map[string]any{"type": "integer", "description": "Max results"},
					},
					"required": []string{"project"},
				},
			},
			{
				Name:        "findings_get",
				Description: "Get finding details by ID",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"finding_id": map[string]any{"type": "string", "description": "Finding ID"},
					},
					"required": []string{"finding_id"},
				},
			},
			{
				Name:        "gate_check",
				Description: "Check gate status for a project",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"project":  map[string]any{"type": "string", "description": "Project slug"},
						"severity": map[string]any{"type": "string", "description": "Severity threshold (default: high,critical)"},
					},
					"required": []string{"project"},
				},
			},
			{
				Name:        "waivers_list",
				Description: "List waivers for a project",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"project": map[string]any{"type": "string", "description": "Project slug"},
					},
					"required": []string{"project"},
				},
			},
			{
				Name:        "waivers_get",
				Description: "Get waiver details",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"project":   map[string]any{"type": "string", "description": "Project slug"},
						"waiver_id": map[string]any{"type": "string", "description": "Waiver ID"},
					},
					"required": []string{"project", "waiver_id"},
				},
			},
			{
				Name:        "waivers_create",
				Description: "Create a new waiver for a project",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"project":     map[string]any{"type": "string", "description": "Project slug"},
						"name":        map[string]any{"type": "string", "description": "Waiver name"},
						"description": map[string]any{"type": "string", "description": "Waiver description"},
						"finding_ids": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Finding IDs to target"},
					},
					"required": []string{"project", "name"},
				},
			},
			{
				Name:        "waivers_toggle",
				Description: "Enable or disable a waiver",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"project":   map[string]any{"type": "string", "description": "Project slug"},
						"waiver_id": map[string]any{"type": "string", "description": "Waiver ID"},
					},
					"required": []string{"project", "waiver_id"},
				},
			},
			{
				Name:        "waiver_events",
				Description: "List events for a waiver",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"project":   map[string]any{"type": "string", "description": "Project slug"},
						"waiver_id": map[string]any{"type": "string", "description": "Waiver ID"},
					},
					"required": []string{"project", "waiver_id"},
				},
			},
		}
		result, _ := json.Marshal(ToolListResult{Tools: tools})
		raw := json.RawMessage(result)
		return jsonRPCMessage{JSONRPC: "2.0", ID: msg.ID, Result: &raw}

	case "tools/call":
		return handleToolCall(api, msg)

	case "notifications/initialized":
		return jsonRPCMessage{JSONRPC: "2.0", ID: msg.ID}

	default:
		return jsonRPCMessage{
			JSONRPC: "2.0",
			ID:      msg.ID,
			Error:   &jsonRPCError{Code: -32601, Message: fmt.Sprintf("method not found: %s", msg.Method)},
		}
	}
}

func handleToolCall(api API, msg jsonRPCMessage) jsonRPCMessage {
	var params struct {
		Name      string           `json:"name"`
		Arguments *json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(*msg.Params, &params); err != nil {
		return errorResponse(msg.ID, -32602, "invalid params")
	}

	if params.Name == "" {
		return errorResponse(msg.ID, -32602, "missing tool name")
	}

	switch params.Name {
	case "findings_list":
		return callFindingsList(api, msg.ID, params.Arguments)
	case "findings_get":
		return callFindingsGet(api, msg.ID, params.Arguments)
	case "gate_check":
		return callGateCheck(api, msg.ID, params.Arguments)
	case "waivers_list":
		return callWaiversList(api, msg.ID, params.Arguments)
	case "waivers_get":
		return callWaiversGet(api, msg.ID, params.Arguments)
	case "waivers_create":
		return callWaiversCreate(api, msg.ID, params.Arguments)
	case "waivers_toggle":
		return callWaiversToggle(api, msg.ID, params.Arguments)
	case "waiver_events":
		return callWaiverEvents(api, msg.ID, params.Arguments)
	default:
		return errorResponse(msg.ID, -32601, fmt.Sprintf("unknown tool: %s", params.Name))
	}
}

func readArgs[T any](args *json.RawMessage) (T, error) {
	var v T
	if args == nil || len(*args) == 0 {
		return v, nil
	}
	err := json.Unmarshal(*args, &v)
	return v, err
}

func callFindingsList(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		Project  string `json:"project"`
		Severity string `json:"severity"`
		Status   string `json:"status"`
		Limit    int    `json:"limit"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, "invalid arguments")
	}
	if a.Project == "" {
		return errorResponse(id, -32602, "project is required")
	}

	var severities, states []string
	if a.Severity != "" {
		severities = strings.Split(a.Severity, ",")
	}
	if a.Status != "" {
		states = strings.Split(a.Status, ",")
	}

	limit := int32(a.Limit)
	if limit <= 0 {
		limit = 50
	}

	findings, err := api.ListFindings(a.Project, severities, states, limit, 0)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	text := fmt.Sprintf("Found %d finding(s):\n", len(findings))
	for _, f := range findings {
		text += fmt.Sprintf("- %s [%s] %s (state: %s, gate: %s)\n", f.ID, f.CurrentSeverity, f.CurrentTitle, f.AnalysisState, f.GateEffect)
	}

	result, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	raw := json.RawMessage(result)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &raw}
}

func callFindingsGet(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		FindingID string `json:"finding_id"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, "invalid arguments")
	}
	if a.FindingID == "" {
		return errorResponse(id, -32602, "finding_id is required")
	}

	f, err := api.GetFinding(a.FindingID)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	score := ""
	if f.CurrentScore != nil {
		score = fmt.Sprintf("%.1f", *f.CurrentScore)
	}
	text := fmt.Sprintf("Finding: %s\nTitle: %s\nSeverity: %s\nScore: %s\nState: %s\nAnalysis: %s\nGate Effect: %s\nFingerprint: %s\nKind: %s",
		f.ID, f.CurrentTitle, f.CurrentSeverity, score, f.State, f.AnalysisState, f.GateEffect, f.Fingerprint, f.FindingKind)

	result, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	raw := json.RawMessage(result)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &raw}
}

func callGateCheck(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		Project  string `json:"project"`
		Severity string `json:"severity"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, "invalid arguments")
	}
	if a.Project == "" {
		return errorResponse(id, -32602, "project is required")
	}

	gs, err := api.GetGateStatus(a.Project, a.Severity)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	var text string
	if gs.ThresholdBreached {
		text = fmt.Sprintf("gate FAILED: %d blocking finding(s)", gs.BlockingCount)
		if len(gs.BlockedBy) > 0 {
			for _, b := range gs.BlockedBy {
				text += fmt.Sprintf("\n  blocked by: %s", b)
			}
		}
	} else {
		text = "gate PASSED: no blocking findings"
	}

	result, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	raw := json.RawMessage(result)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &raw}
}

func callWaiversList(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		Project string `json:"project"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, "invalid arguments")
	}
	if a.Project == "" {
		return errorResponse(id, -32602, "project is required")
	}

	waivers, err := api.ListWaivers(a.Project)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	if len(waivers) == 0 {
		result, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": "No waivers found."}}})
		raw := json.RawMessage(result)
		return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &raw}
	}

	text := fmt.Sprintf("Found %d waiver(s):\n", len(waivers))
	for _, w := range waivers {
		status := "enabled"
		if !w.Enabled {
			status = "disabled"
		}
		text += fmt.Sprintf("- %s [%s] %s\n", w.ID, status, w.Name)
	}

	result, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	raw := json.RawMessage(result)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &raw}
}

func callWaiversGet(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		Project  string `json:"project"`
		WaiverID string `json:"waiver_id"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, "invalid arguments")
	}
	if a.Project == "" || a.WaiverID == "" {
		return errorResponse(id, -32602, "project and waiver_id are required")
	}

	w, err := api.GetWaiver(a.Project, a.WaiverID)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	status := "enabled"
	if !w.Enabled {
		status = "disabled"
	}
	text := fmt.Sprintf("Waiver: %s\nName: %s\nDescription: %s\nStatus: %s\nConditions: %d\nContexts: %d\nTargets: %d",
		w.ID, w.Name, w.Description, status, len(w.Conditions), len(w.Contexts), len(w.Targets))

	result, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	raw := json.RawMessage(result)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &raw}
}

func callWaiversCreate(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		Project     string   `json:"project"`
		Name        string   `json:"name"`
		Description string   `json:"description"`
		FindingIDs  []string `json:"finding_ids"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, "invalid arguments")
	}
	if a.Project == "" || a.Name == "" {
		return errorResponse(id, -32602, "project and name are required")
	}

	w, err := api.CreateWaiver(a.Project, &client.CreateWaiverRequest{
		Name:        a.Name,
		Description: a.Description,
		TargetIDs:   a.FindingIDs,
	})
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	text := fmt.Sprintf("Waiver created: %s (%s)", w.ID, w.Name)
	result, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	raw := json.RawMessage(result)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &raw}
}

func callWaiversToggle(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		Project  string `json:"project"`
		WaiverID string `json:"waiver_id"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, "invalid arguments")
	}
	if a.Project == "" || a.WaiverID == "" {
		return errorResponse(id, -32602, "project and waiver_id are required")
	}

	w, err := api.ToggleWaiver(a.Project, a.WaiverID)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	status := "enabled"
	if !w.Enabled {
		status = "disabled"
	}
	text := fmt.Sprintf("Waiver %s is now %s", w.ID, status)
	result, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	raw := json.RawMessage(result)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &raw}
}

func callWaiverEvents(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		Project  string `json:"project"`
		WaiverID string `json:"waiver_id"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, "invalid arguments")
	}
	if a.Project == "" || a.WaiverID == "" {
		return errorResponse(id, -32602, "project and waiver_id are required")
	}

	events, err := api.ListWaiverEvents(a.Project, a.WaiverID)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	text := fmt.Sprintf("Found %d event(s):\n", len(events))
	for _, e := range events {
		text += fmt.Sprintf("- %s: %s (%s)\n", e.ID, e.EventType, e.CreatedAt)
	}

	result, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	raw := json.RawMessage(result)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &raw}
}

func errorResponse(id any, code int, message string) jsonRPCMessage {
	return jsonRPCMessage{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &jsonRPCError{Code: code, Message: message},
	}
}

func sendResponse(w io.Writer, msg jsonRPCMessage) {
	data, _ := json.Marshal(msg)
	fmt.Fprintln(w, string(data))
}

func main() {
	apiURL := os.Getenv("API_URL")
	if apiURL == "" {
		apiURL = "http://localhost:8080"
	}

	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		log.Fatal("API_KEY environment variable is required")
	}

	cl := client.New(apiURL, client.WithToken(apiKey))

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		msg, err := parseMessage([]byte(line))
		if err != nil {
			sendResponse(os.Stdout, errorResponse(nil, -32700, "parse error: "+err.Error()))
			continue
		}

		resp := handleMessage(cl, msg)
		if resp.ID != nil {
			sendResponse(os.Stdout, resp)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Fatalf("stdin error: %v", err)
	}
}
