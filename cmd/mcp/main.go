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
	GetIntroducedGateStatus(projectSlug string, severity string, reportID string) (*client.GateStatus, error)
	PreviewPRCheck(projectSlug string, commit string, provider string, reportID string, severity string) (*client.PRCheckPreview, error)
	PreviewPatch(findingID string) (*client.PatchOutcome, error)
	PreviewNotification(findingID string, channel string, target string, linked bool) (*client.NotifyOutcome, error)
	GetAdminStatus() (*client.AdminStatus, error)
	PreviewRetention(days int) (*client.RetentionPreview, error)
	GetEffectivePolicy(projectSlug string) (*client.PolicyEffective, error)
	ListTeams() ([]client.Team, error)
	ListProjectTeams(projectSlug string) ([]client.ProjectTeam, error)
	UpsertReachability(findingID, state, evidence string) (*client.ReachabilityAssessment, error)
	ListReachability(findingID string) ([]client.ReachabilityAssessment, error)
	GetWatcherStatus() (*client.WatcherStatus, error)
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

const (
	descProjectSlug        = "Project slug"
	descFindingID          = "Finding ID"
	descWaiverID           = "Waiver ID"
	msgInvalidArguments    = "invalid arguments"
	msgProjectRequired     = "project is required"
	msgFindingIDRequired   = "finding_id is required"
	msgProjectWaiverNeeded = "project and waiver_id are required"
)

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
						"project":  map[string]any{"type": "string", "description": descProjectSlug},
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
						"finding_id": map[string]any{"type": "string", "description": descFindingID},
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
						"project":         map[string]any{"type": "string", "description": descProjectSlug},
						"severity":        map[string]any{"type": "string", "description": "Severity threshold (default: high,critical)"},
						"introduced_only": map[string]any{"type": "boolean", "description": "Only findings introduced by report_id"},
						"report_id":       map[string]any{"type": "string", "description": "Report ID (required with introduced_only)"},
					},
					"required": []string{"project"},
				},
			},
			{
				Name:        "pr_preview",
				Description: "Preview the pull-request check for a commit (dry-run; publishes nothing)",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"project":   map[string]any{"type": "string", "description": descProjectSlug},
						"commit":    map[string]any{"type": "string", "description": "Commit SHA under review"},
						"provider":  map[string]any{"type": "string", "description": "Provider (default: github)"},
						"report_id": map[string]any{"type": "string", "description": "Report ID for an exact-scan tie"},
						"severity":  map[string]any{"type": "string", "description": "Severity threshold"},
					},
					"required": []string{"project", "commit"},
				},
			},
			{
				Name:        "patch_preview",
				Description: "Preview the safe patch for a finding (dry-run; applies nothing)",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"finding_id": map[string]any{"type": "string", "description": descFindingID},
					},
					"required": []string{"finding_id"},
				},
			},
			{
				Name:        "notify_preview",
				Description: "Preview the tracker/messaging action for a finding (dry-run; sends nothing)",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"finding_id": map[string]any{"type": "string", "description": descFindingID},
						"channel":    map[string]any{"type": "string", "description": "issue or message"},
						"target":     map[string]any{"type": "string", "description": "Integration and scope"},
						"linked":     map[string]any{"type": "boolean", "description": "Whether a work item is already linked"},
					},
					"required": []string{"finding_id", "channel", "target"},
				},
			},
			{
				Name:        "admin_status",
				Description: "Platform observability snapshot (admin only)",
				InputSchema: map[string]any{
					"type":       "object",
					"properties": map[string]any{},
				},
			},
			{
				Name:        "admin_retention_preview",
				Description: "Count settled reports a purge would delete (dry-run; deletes nothing)",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"days": map[string]any{"type": "integer", "description": "Window in days (1-3650)"},
					},
					"required": []string{"days"},
				},
			},
			{
				Name:        "policy_effective",
				Description: "Show a project's resolved policy with provenance",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"project": map[string]any{"type": "string", "description": descProjectSlug},
					},
					"required": []string{"project"},
				},
			},
			{
				Name:        "teams_list",
				Description: "List all teams",
				InputSchema: map[string]any{
					"type":       "object",
					"properties": map[string]any{},
				},
			},
			{
				Name:        "project_teams",
				Description: "List teams linked to a project with conferred roles",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"project": map[string]any{"type": "string", "description": descProjectSlug},
					},
					"required": []string{"project"},
				},
			},
			{
				Name:        "reachability_set",
				Description: "Set a finding's reachability assessment (reachable, not_reachable, unknown, not_applicable)", InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"finding_id": map[string]any{"type": "string", "description": descFindingID},
						"state":      map[string]any{"type": "string", "description": "reachable | not_reachable | unknown | not_applicable"},
						"evidence":   map[string]any{"type": "string", "description": "Optional evidence note"},
					},
					"required": []string{"finding_id", "state"},
				},
			},
			{
				Name:        "watcher_status",
				Description: "Check CVE watcher daemon health (last poll, failures)",
				InputSchema: map[string]any{
					"type":       "object",
					"properties": map[string]any{},
				},
			},
			{
				Name:        "waivers_list",
				Description: "List waivers for a project",
				InputSchema: map[string]any{
					"type": "object",
					"properties": map[string]any{
						"project": map[string]any{"type": "string", "description": descProjectSlug},
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
						"project":   map[string]any{"type": "string", "description": descProjectSlug},
						"waiver_id": map[string]any{"type": "string", "description": descWaiverID},
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
						"project":     map[string]any{"type": "string", "description": descProjectSlug},
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
						"project":   map[string]any{"type": "string", "description": descProjectSlug},
						"waiver_id": map[string]any{"type": "string", "description": descWaiverID},
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
						"project":   map[string]any{"type": "string", "description": descProjectSlug},
						"waiver_id": map[string]any{"type": "string", "description": descWaiverID},
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
	case "pr_preview":
		return callPRPreview(api, msg.ID, params.Arguments)
	case "patch_preview":
		return callPatchPreview(api, msg.ID, params.Arguments)
	case "notify_preview":
		return callNotifyPreview(api, msg.ID, params.Arguments)
	case "admin_status":
		return callAdminStatus(api, msg.ID)
	case "admin_retention_preview":
		return callAdminRetentionPreview(api, msg.ID, params.Arguments)
	case "policy_effective":
		return callPolicyEffective(api, msg.ID, params.Arguments)
	case "teams_list":
		return callTeamsList(api, msg.ID)
	case "project_teams":
		return callProjectTeams(api, msg.ID, params.Arguments)
	case "reachability_set":
		return callReachabilitySet(api, msg.ID, params.Arguments)
	case "watcher_status":
		return callWatcherStatus(api, msg.ID)
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
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.Project == "" {
		return errorResponse(id, -32602, msgProjectRequired)
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
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.FindingID == "" {
		return errorResponse(id, -32602, msgFindingIDRequired)
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
	if f.IntroducedCommitSha != nil && *f.IntroducedCommitSha != "" {
		text += fmt.Sprintf("\nIntroduced: %s", *f.IntroducedCommitSha)
	} else {
		text += "\nIntroduced: unattributed"
	}

	result, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	raw := json.RawMessage(result)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &raw}
}

func callGateCheck(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		Project        string `json:"project"`
		Severity       string `json:"severity"`
		IntroducedOnly bool   `json:"introduced_only"`
		ReportID       string `json:"report_id"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.Project == "" {
		return errorResponse(id, -32602, msgProjectRequired)
	}
	if a.IntroducedOnly && a.ReportID == "" {
		return errorResponse(id, -32602, "report_id is required with introduced_only")
	}

	var gs *client.GateStatus
	if a.IntroducedOnly {
		gs, err = api.GetIntroducedGateStatus(a.Project, a.Severity, a.ReportID)
	} else {
		gs, err = api.GetGateStatus(a.Project, a.Severity)
	}
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	var text string
	if gs.ThresholdBreached {
		text = fmt.Sprintf("gate FAILED: %d blocking finding(s)", gs.BlockingCount)
		if len(gs.BlockedBy) > 0 {
			for _, b := range gs.BlockedBy {
				reach := "unknown"
				if r, ok := gs.BlockedByReachability[b]; ok && r != "" {
					reach = r
				}
				text += fmt.Sprintf("\n  blocked by: %s (reachability: %s)", b, reach)
			}
		}
	} else {
		text = "gate PASSED: no blocking findings"
	}

	result, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	raw := json.RawMessage(result)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &raw}
}

func callPRPreview(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		Project  string `json:"project"`
		Commit   string `json:"commit"`
		Provider string `json:"provider"`
		ReportID string `json:"report_id"`
		Severity string `json:"severity"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.Project == "" {
		return errorResponse(id, -32602, msgProjectRequired)
	}
	if a.Commit == "" {
		return errorResponse(id, -32602, "commit is required")
	}

	preview, err := api.PreviewPRCheck(a.Project, a.Commit, a.Provider, a.ReportID, a.Severity)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	text := fmt.Sprintf("check %s: %s\n%s", preview.Conclusion, preview.Title, preview.Summary)
	for _, an := range preview.Annotations {
		text += fmt.Sprintf("\n  %s:%d %s", an.File, an.StartLine, an.Title)
	}
	previewResult, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	previewRaw := json.RawMessage(previewResult)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &previewRaw}
}

func callPatchPreview(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		FindingID string `json:"finding_id"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.FindingID == "" {
		return errorResponse(id, -32602, msgFindingIDRequired)
	}

	outcome, err := api.PreviewPatch(a.FindingID)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	var text string
	if !outcome.Supported || outcome.Proposal == nil {
		text = fmt.Sprintf("no patch: %s", outcome.Reason)
	} else {
		p := outcome.Proposal
		text = fmt.Sprintf("patch %s (%s, confidence %s)\n%s", p.ID, p.Class, p.Confidence, p.Rationale)
		for _, e := range p.Edits {
			text += fmt.Sprintf("\n  %s %s %s %s -> %s", e.Operation, e.File, e.Package, e.FromVersion, e.ToVersion)
		}
		text += fmt.Sprintf("\nverify: %s", p.VerifyBy)
	}
	patchResult, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	patchRaw := json.RawMessage(patchResult)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &patchRaw}
}

func callNotifyPreview(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		FindingID string `json:"finding_id"`
		Channel   string `json:"channel"`
		Target    string `json:"target"`
		Linked    bool   `json:"linked"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.FindingID == "" {
		return errorResponse(id, -32602, msgFindingIDRequired)
	}
	if a.Channel == "" {
		return errorResponse(id, -32602, "channel is required")
	}
	if a.Target == "" {
		return errorResponse(id, -32602, "target is required")
	}

	outcome, err := api.PreviewNotification(a.FindingID, a.Channel, a.Target, a.Linked)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	var text string
	if !outcome.Supported || outcome.Plan == nil {
		text = fmt.Sprintf("no notification: %s", outcome.Reason)
	} else {
		p := outcome.Plan
		text = fmt.Sprintf("notify %s (%s -> %s): %s\n%s\ndedupe: %s", p.ID, p.Channel, p.Target, p.Title, p.Body, p.DedupeKey)
	}
	notifyResult, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	notifyRaw := json.RawMessage(notifyResult)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &notifyRaw}
}

func callAdminStatus(api API, id any) jsonRPCMessage {
	status, err := api.GetAdminStatus()
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}
	text := fmt.Sprintf(
		"projects=%d users=%d open_findings=%d reports=%d",
		status.Projects, status.Users, status.OpenFindings, status.Reports,
	)
	adminResult, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	adminRaw := json.RawMessage(adminResult)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &adminRaw}
}

func callAdminRetentionPreview(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		Days int `json:"days"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.Days <= 0 {
		return errorResponse(id, -32602, "days is required")
	}

	preview, err := api.PreviewRetention(a.Days)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}
	text := fmt.Sprintf(
		"%d settled report(s) older than %d day(s) would be deleted",
		preview.StaleReports, preview.OlderThanDays,
	)
	retentionResult, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	retentionRaw := json.RawMessage(retentionResult)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &retentionRaw}
}

func callPolicyEffective(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		Project string `json:"project"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.Project == "" {
		return errorResponse(id, -32602, msgProjectRequired)
	}

	eff, err := api.GetEffectivePolicy(a.Project)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}
	template := "(none)"
	if eff.TemplateName != nil {
		template = fmt.Sprintf("%s v%d", *eff.TemplateName, eff.TemplateVersion)
	}
	text := fmt.Sprintf(
		"template: %s\nfloor=%s (%s) watcher=%s (%s)",
		template, eff.SeverityFloor, eff.SeveritySource, eff.WatcherGate, eff.WatcherSource,
	)
	policyResult, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	policyRaw := json.RawMessage(policyResult)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &policyRaw}
}

func callTeamsList(api API, id any) jsonRPCMessage {
	teams, err := api.ListTeams()
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}
	var text string
	if len(teams) == 0 {
		text = "No teams."
	}
	for _, t := range teams {
		text += fmt.Sprintf("%s (%s)\n", t.Name, t.ID)
	}
	teamsResult, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": strings.TrimSpace(text)}}})
	teamsRaw := json.RawMessage(teamsResult)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &teamsRaw}
}

func callProjectTeams(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		Project string `json:"project"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.Project == "" {
		return errorResponse(id, -32602, msgProjectRequired)
	}

	links, err := api.ListProjectTeams(a.Project)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}
	var text string
	if len(links) == 0 {
		text = "No linked teams."
	}
	for _, l := range links {
		text += fmt.Sprintf("%s (%s) as %s\n", l.TeamName, l.TeamID, l.Role)
	}
	linksResult, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": strings.TrimSpace(text)}}})
	linksRaw := json.RawMessage(linksResult)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &linksRaw}
}

func callReachabilitySet(api API, id any, args *json.RawMessage) jsonRPCMessage {
	a, err := readArgs[struct {
		FindingID string `json:"finding_id"`
		State     string `json:"state"`
		Evidence  string `json:"evidence"`
	}](args)
	if err != nil {
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.FindingID == "" || a.State == "" {
		return errorResponse(id, -32602, "finding_id and state are required")
	}

	assess, err := api.UpsertReachability(a.FindingID, a.State, a.Evidence)
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}

	text := fmt.Sprintf("reachability set: finding=%s state=%s", assess.FindingID, assess.State)
	if assess.Evidence != "" {
		text += fmt.Sprintf(" evidence=%q", assess.Evidence)
	}
	result, _ := json.Marshal(map[string]any{"content": []map[string]string{{"type": "text", "text": text}}})
	raw := json.RawMessage(result)
	return jsonRPCMessage{JSONRPC: "2.0", ID: id, Result: &raw}
}

func callWatcherStatus(api API, id any) jsonRPCMessage {
	ws, err := api.GetWatcherStatus()
	if err != nil {
		return errorResponse(id, -32603, err.Error())
	}
	var text string
	if ws.LastSuccessfulPollAt != "" {
		text = fmt.Sprintf("last successful poll: %s", ws.LastSuccessfulPollAt)
	} else {
		text = "last successful poll: never (cold start)"
	}
	if ws.LastPollAttemptAt != "" {
		text += fmt.Sprintf("\nlast poll attempt: %s", ws.LastPollAttemptAt)
	}
	if ws.LastError != "" {
		text += fmt.Sprintf("\nlast error: %s", ws.LastError)
	}
	text += fmt.Sprintf("\nconsecutive failures: %d", ws.ConsecutiveFailures)
	switch {
	case ws.Healthy:
		text += "\nstatus: healthy"
	case ws.Stale:
		text += fmt.Sprintf("\nstatus: STALE (no successful poll within %s)", ws.StalenessWindow)
	default:
		text += "\nstatus: FAILING"
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
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.Project == "" {
		return errorResponse(id, -32602, msgProjectRequired)
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
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.Project == "" || a.WaiverID == "" {
		return errorResponse(id, -32602, msgProjectWaiverNeeded)
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
		return errorResponse(id, -32602, msgInvalidArguments)
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
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.Project == "" || a.WaiverID == "" {
		return errorResponse(id, -32602, msgProjectWaiverNeeded)
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
		return errorResponse(id, -32602, msgInvalidArguments)
	}
	if a.Project == "" || a.WaiverID == "" {
		return errorResponse(id, -32602, msgProjectWaiverNeeded)
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
