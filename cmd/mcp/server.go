package main

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/minh-tg/specht/internal/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
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

type findingsListInput struct {
	Project  string `json:"project" jsonschema:"project slug"`
	Severity string `json:"severity,omitempty" jsonschema:"comma-separated severity filter"`
	Status   string `json:"status,omitempty" jsonschema:"comma-separated status filter"`
	Limit    int    `json:"limit,omitempty" jsonschema:"maximum number of results"`
}

type findingInput struct {
	FindingID string `json:"finding_id" jsonschema:"finding ID"`
}

type gateCheckInput struct {
	Project        string `json:"project" jsonschema:"project slug"`
	Severity       string `json:"severity,omitempty" jsonschema:"severity threshold"`
	IntroducedOnly bool   `json:"introduced_only,omitempty" jsonschema:"only findings introduced by a report"`
	ReportID       string `json:"report_id,omitempty" jsonschema:"report ID used with introduced_only"`
}

type prPreviewInput struct {
	Project  string `json:"project" jsonschema:"project slug"`
	Commit   string `json:"commit" jsonschema:"commit SHA under review"`
	Provider string `json:"provider,omitempty" jsonschema:"provider name"`
	ReportID string `json:"report_id,omitempty" jsonschema:"report ID for an exact-scan tie"`
	Severity string `json:"severity,omitempty" jsonschema:"severity threshold"`
}

type notifyPreviewInput struct {
	FindingID string `json:"finding_id" jsonschema:"finding ID"`
	Channel   string `json:"channel" jsonschema:"issue or message"`
	Target    string `json:"target" jsonschema:"integration and scope"`
	Linked    bool   `json:"linked,omitempty" jsonschema:"whether a work item is already linked"`
}

type retentionPreviewInput struct {
	Days int `json:"days" jsonschema:"retention window in days"`
}

type projectInput struct {
	Project string `json:"project" jsonschema:"project slug"`
}

type reachabilitySetInput struct {
	FindingID string `json:"finding_id" jsonschema:"finding ID"`
	State     string `json:"state" jsonschema:"reachable, not_reachable, unknown, or not_applicable"`
	Evidence  string `json:"evidence,omitempty" jsonschema:"optional evidence note"`
}

type waiverInput struct {
	Project  string `json:"project" jsonschema:"project slug"`
	WaiverID string `json:"waiver_id" jsonschema:"waiver ID"`
}

type waiverCreateInput struct {
	Project     string `json:"project" jsonschema:"project slug"`
	Name        string `json:"name" jsonschema:"waiver name"`
	Description string `json:"description,omitempty" jsonschema:"waiver description"`
	// ExpiresAt is the RFC3339 expiry; the API validates the format and
	// rejects malformed timestamps at the edge.
	ExpiresAt  string   `json:"expires_at,omitempty" jsonschema:"RFC3339 expiry timestamp"`
	FindingIDs []string `json:"finding_ids,omitempty" jsonschema:"finding IDs to target"`
}

// toolOptions decides which tools a server exposes. The default is the
// narrowest useful set: read-only tools that a project API key can call.
type toolOptions struct {
	// AllowMutations registers the tools that change state (waivers,
	// reachability). Off by default because the agent on the other end acts on
	// scanner-supplied text, which can be written by an attacker; a prompt
	// injected there could otherwise suppress findings without a human
	// seeing it.
	AllowMutations bool
	// SessionCredential means API_KEY holds a user session token, not a
	// project API key. The admin, team-directory and watcher routes accept
	// sessions only, so their tools are registered only for one.
	SessionCredential bool
}

// loadToolOptions derives the tool surface from the credential and the
// environment. MCP_ALLOW_MUTATIONS is strict so a typo cannot silently enable
// or disable the write tools.
func loadToolOptions(apiKey string, getenv func(string) string) (toolOptions, error) {
	opts := toolOptions{SessionCredential: !strings.HasPrefix(apiKey, "vuln_")}
	if v := getenv("MCP_ALLOW_MUTATIONS"); v != "" {
		allow, err := strconv.ParseBool(v)
		if err != nil {
			return toolOptions{}, fmt.Errorf("MCP_ALLOW_MUTATIONS is invalid: %q (want true or false)", v)
		}
		opts.AllowMutations = allow
	}
	return opts, nil
}

func newMCPServer(api API, opts toolOptions) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "specht-mcp", Version: "0.1.0"}, nil)
	registerReadTools(server, api)
	if opts.SessionCredential {
		registerSessionTools(server, api)
	}
	if opts.AllowMutations {
		registerMutationTools(server, api)
	}
	return server
}

// registerReadTools adds the read-only tools every credential can use.
func registerReadTools(server *mcp.Server, api API) {
	mcp.AddTool(server, &mcp.Tool{Name: "findings_list", Description: "List findings for a project"}, func(_ context.Context, _ *mcp.CallToolRequest, input findingsListInput) (*mcp.CallToolResult, any, error) {
		return handleFindingsList(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "findings_get", Description: "Get finding details by ID"}, func(_ context.Context, _ *mcp.CallToolRequest, input findingInput) (*mcp.CallToolResult, any, error) {
		return handleFindingsGet(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "gate_check", Description: "Check gate status for a project"}, func(_ context.Context, _ *mcp.CallToolRequest, input gateCheckInput) (*mcp.CallToolResult, any, error) {
		return handleGateCheck(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "pr_preview", Description: "Preview the pull-request check for a commit"}, func(_ context.Context, _ *mcp.CallToolRequest, input prPreviewInput) (*mcp.CallToolResult, any, error) {
		return handlePRPreview(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "patch_preview", Description: "Preview the safe patch for a finding"}, func(_ context.Context, _ *mcp.CallToolRequest, input findingInput) (*mcp.CallToolResult, any, error) {
		return handlePatchPreview(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "notify_preview", Description: "Preview the tracker or messaging action for a finding"}, func(_ context.Context, _ *mcp.CallToolRequest, input notifyPreviewInput) (*mcp.CallToolResult, any, error) {
		return handleNotifyPreview(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "policy_effective", Description: "Show a project's resolved policy with provenance"}, func(_ context.Context, _ *mcp.CallToolRequest, input projectInput) (*mcp.CallToolResult, any, error) {
		return handlePolicyEffective(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "project_teams", Description: "List teams linked to a project"}, func(_ context.Context, _ *mcp.CallToolRequest, input projectInput) (*mcp.CallToolResult, any, error) {
		return handleProjectTeams(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "waivers_list", Description: "List waivers for a project"}, func(_ context.Context, _ *mcp.CallToolRequest, input projectInput) (*mcp.CallToolResult, any, error) {
		return handleWaiversList(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "waivers_get", Description: "Get waiver details"}, func(_ context.Context, _ *mcp.CallToolRequest, input waiverInput) (*mcp.CallToolResult, any, error) {
		return handleWaiversGet(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "waiver_events", Description: "List events for a waiver"}, func(_ context.Context, _ *mcp.CallToolRequest, input waiverInput) (*mcp.CallToolResult, any, error) {
		return handleWaiverEvents(api, input)
	})
}

// registerSessionTools adds the tools whose routes reject API keys.
func registerSessionTools(server *mcp.Server, api API) {
	mcp.AddTool(server, &mcp.Tool{Name: "admin_status", Description: "Platform observability snapshot"}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return handleAdminStatus(api)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "admin_retention_preview", Description: "Count settled reports a purge would delete"}, func(_ context.Context, _ *mcp.CallToolRequest, input retentionPreviewInput) (*mcp.CallToolResult, any, error) {
		return handleAdminRetentionPreview(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "teams_list", Description: "List all teams"}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return handleTeamsList(api)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "watcher_status", Description: "Check CVE watcher daemon health"}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return handleWatcherStatus(api)
	})
}

// registerMutationTools adds the tools that change state.
func registerMutationTools(server *mcp.Server, api API) {
	mcp.AddTool(server, &mcp.Tool{Name: "reachability_set", Description: "Set a finding's reachability assessment"}, func(_ context.Context, _ *mcp.CallToolRequest, input reachabilitySetInput) (*mcp.CallToolResult, any, error) {
		return handleReachabilitySet(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "waivers_create", Description: "Create a new waiver for a project"}, func(_ context.Context, _ *mcp.CallToolRequest, input waiverCreateInput) (*mcp.CallToolResult, any, error) {
		return handleWaiversCreate(api, input)
	})
	mcp.AddTool(server, &mcp.Tool{Name: "waivers_toggle", Description: "Enable or disable a waiver"}, func(_ context.Context, _ *mcp.CallToolRequest, input waiverInput) (*mcp.CallToolResult, any, error) {
		return handleWaiversToggle(api, input)
	})
}

func textToolResult(text string) (*mcp.CallToolResult, any, error) {
	return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
}

func handleFindingsList(api API, input findingsListInput) (*mcp.CallToolResult, any, error) {
	if input.Project == "" {
		return nil, nil, fmt.Errorf("project is required")
	}
	var severities, states []string
	if input.Severity != "" {
		severities = strings.Split(input.Severity, ",")
	}
	if input.Status != "" {
		states = strings.Split(input.Status, ",")
	}
	limit := int32(input.Limit)
	if limit <= 0 {
		limit = 50
	}
	findings, err := api.ListFindings(input.Project, severities, states, limit, 0)
	if err != nil {
		return nil, nil, err
	}
	var text strings.Builder
	fmt.Fprintf(&text, "Found %d finding(s):\n", len(findings))
	for _, finding := range findings {
		fmt.Fprintf(&text, "- %s [%s] %s (state: %s, gate: %s)\n", finding.ID, finding.CurrentSeverity, finding.CurrentTitle, finding.AnalysisState, finding.GateEffect)
	}
	return textToolResult(text.String())
}

func handleFindingsGet(api API, input findingInput) (*mcp.CallToolResult, any, error) {
	if input.FindingID == "" {
		return nil, nil, fmt.Errorf("finding_id is required")
	}
	finding, err := api.GetFinding(input.FindingID)
	if err != nil {
		return nil, nil, err
	}
	score := ""
	if finding.CurrentScore != nil {
		score = fmt.Sprintf("%.1f", *finding.CurrentScore)
	}
	text := fmt.Sprintf("Finding: %s\nTitle: %s\nSeverity: %s\nScore: %s\nState: %s\nAnalysis: %s\nGate Effect: %s\nFingerprint: %s\nKind: %s", finding.ID, finding.CurrentTitle, finding.CurrentSeverity, score, finding.State, finding.AnalysisState, finding.GateEffect, finding.Fingerprint, finding.FindingKind)
	if finding.IntroducedCommitSha != nil && *finding.IntroducedCommitSha != "" {
		text += fmt.Sprintf("\nIntroduced: %s", *finding.IntroducedCommitSha)
	} else {
		text += "\nIntroduced: unattributed"
	}
	return textToolResult(text)
}

func handleGateCheck(api API, input gateCheckInput) (*mcp.CallToolResult, any, error) {
	if input.Project == "" {
		return nil, nil, fmt.Errorf("project is required")
	}
	if input.IntroducedOnly && input.ReportID == "" {
		return nil, nil, fmt.Errorf("report_id is required with introduced_only")
	}
	var status *client.GateStatus
	var err error
	if input.IntroducedOnly {
		status, err = api.GetIntroducedGateStatus(input.Project, input.Severity, input.ReportID)
	} else {
		status, err = api.GetGateStatus(input.Project, input.Severity)
	}
	if err != nil {
		return nil, nil, err
	}
	if !status.ThresholdBreached {
		return textToolResult("gate PASSED: no blocking findings")
	}
	text := fmt.Sprintf("gate FAILED: %d blocking finding(s)", status.BlockingCount)
	for _, id := range status.BlockedBy {
		reachability := status.BlockedByReachability[id]
		if reachability == "" {
			reachability = "unknown"
		}
		text += fmt.Sprintf("\n  blocked by: %s (reachability: %s)", id, reachability)
	}
	return textToolResult(text)
}

func handlePRPreview(api API, input prPreviewInput) (*mcp.CallToolResult, any, error) {
	if input.Project == "" {
		return nil, nil, fmt.Errorf("project is required")
	}
	if input.Commit == "" {
		return nil, nil, fmt.Errorf("commit is required")
	}
	preview, err := api.PreviewPRCheck(input.Project, input.Commit, input.Provider, input.ReportID, input.Severity)
	if err != nil {
		return nil, nil, err
	}
	text := fmt.Sprintf("check %s: %s\n%s", preview.Conclusion, preview.Title, preview.Summary)
	for _, annotation := range preview.Annotations {
		text += fmt.Sprintf("\n  %s:%d %s", annotation.File, annotation.StartLine, annotation.Title)
	}
	return textToolResult(text)
}

func handlePatchPreview(api API, input findingInput) (*mcp.CallToolResult, any, error) {
	if input.FindingID == "" {
		return nil, nil, fmt.Errorf("finding_id is required")
	}
	outcome, err := api.PreviewPatch(input.FindingID)
	if err != nil {
		return nil, nil, err
	}
	if !outcome.Supported || outcome.Proposal == nil {
		return textToolResult(fmt.Sprintf("no patch: %s", outcome.Reason))
	}
	proposal := outcome.Proposal
	text := fmt.Sprintf("patch %s (%s, confidence %s)\n%s", proposal.ID, proposal.Class, proposal.Confidence, proposal.Rationale)
	for _, edit := range proposal.Edits {
		text += fmt.Sprintf("\n  %s %s %s %s -> %s", edit.Operation, edit.File, edit.Package, edit.FromVersion, edit.ToVersion)
	}
	text += fmt.Sprintf("\nverify: %s", proposal.VerifyBy)
	return textToolResult(text)
}

func handleNotifyPreview(api API, input notifyPreviewInput) (*mcp.CallToolResult, any, error) {
	if input.FindingID == "" {
		return nil, nil, fmt.Errorf("finding_id is required")
	}
	if input.Channel == "" {
		return nil, nil, fmt.Errorf("channel is required")
	}
	if input.Target == "" {
		return nil, nil, fmt.Errorf("target is required")
	}
	outcome, err := api.PreviewNotification(input.FindingID, input.Channel, input.Target, input.Linked)
	if err != nil {
		return nil, nil, err
	}
	if !outcome.Supported || outcome.Plan == nil {
		return textToolResult(fmt.Sprintf("no notification: %s", outcome.Reason))
	}
	plan := outcome.Plan
	return textToolResult(fmt.Sprintf("notify %s (%s -> %s): %s\n%s\ndedupe: %s", plan.ID, plan.Channel, plan.Target, plan.Title, plan.Body, plan.DedupeKey))
}

func handleAdminStatus(api API) (*mcp.CallToolResult, any, error) {
	status, err := api.GetAdminStatus()
	if err != nil {
		return nil, nil, err
	}
	return textToolResult(fmt.Sprintf("projects=%d users=%d open_findings=%d reports=%d", status.Projects, status.Users, status.OpenFindings, status.Reports))
}

func handleAdminRetentionPreview(api API, input retentionPreviewInput) (*mcp.CallToolResult, any, error) {
	if input.Days <= 0 {
		return nil, nil, fmt.Errorf("days is required")
	}
	preview, err := api.PreviewRetention(input.Days)
	if err != nil {
		return nil, nil, err
	}
	return textToolResult(fmt.Sprintf("%d settled report(s) older than %d day(s) would be deleted", preview.StaleReports, preview.OlderThanDays))
}

func handlePolicyEffective(api API, input projectInput) (*mcp.CallToolResult, any, error) {
	if input.Project == "" {
		return nil, nil, fmt.Errorf("project is required")
	}
	effective, err := api.GetEffectivePolicy(input.Project)
	if err != nil {
		return nil, nil, err
	}
	template := "(none)"
	if effective.TemplateName != nil {
		template = fmt.Sprintf("%s v%d", *effective.TemplateName, effective.TemplateVersion)
	}
	return textToolResult(fmt.Sprintf("template: %s\nfloor=%s (%s) watcher=%s (%s)", template, effective.SeverityFloor, effective.SeveritySource, effective.WatcherGate, effective.WatcherSource))
}

func handleTeamsList(api API) (*mcp.CallToolResult, any, error) {
	teams, err := api.ListTeams()
	if err != nil {
		return nil, nil, err
	}
	if len(teams) == 0 {
		return textToolResult("No teams.")
	}
	var text strings.Builder
	for _, team := range teams {
		fmt.Fprintf(&text, "%s (%s)\n", team.Name, team.ID)
	}
	return textToolResult(strings.TrimSpace(text.String()))
}

func handleProjectTeams(api API, input projectInput) (*mcp.CallToolResult, any, error) {
	if input.Project == "" {
		return nil, nil, fmt.Errorf("project is required")
	}
	links, err := api.ListProjectTeams(input.Project)
	if err != nil {
		return nil, nil, err
	}
	if len(links) == 0 {
		return textToolResult("No linked teams.")
	}
	var text strings.Builder
	for _, link := range links {
		fmt.Fprintf(&text, "%s (%s) as %s\n", link.TeamName, link.TeamID, link.Role)
	}
	return textToolResult(strings.TrimSpace(text.String()))
}

func handleReachabilitySet(api API, input reachabilitySetInput) (*mcp.CallToolResult, any, error) {
	if input.FindingID == "" || input.State == "" {
		return nil, nil, fmt.Errorf("finding_id and state are required")
	}
	assessment, err := api.UpsertReachability(input.FindingID, input.State, input.Evidence)
	if err != nil {
		return nil, nil, err
	}
	text := fmt.Sprintf("reachability set: finding=%s state=%s", assessment.FindingID, assessment.State)
	if assessment.Evidence != "" {
		text += fmt.Sprintf(" evidence=%q", assessment.Evidence)
	}
	return textToolResult(text)
}

func handleWatcherStatus(api API) (*mcp.CallToolResult, any, error) {
	status, err := api.GetWatcherStatus()
	if err != nil {
		return nil, nil, err
	}
	var text string
	if status.LastSuccessfulPollAt != "" {
		text = fmt.Sprintf("last successful poll: %s", status.LastSuccessfulPollAt)
	} else {
		text = "last successful poll: never (cold start)"
	}
	if status.LastPollAttemptAt != "" {
		text += fmt.Sprintf("\nlast poll attempt: %s", status.LastPollAttemptAt)
	}
	if status.LastError != "" {
		text += fmt.Sprintf("\nlast error: %s", status.LastError)
	}
	text += fmt.Sprintf("\nconsecutive failures: %d", status.ConsecutiveFailures)
	switch {
	case status.Healthy:
		text += "\nstatus: healthy"
	case status.Stale:
		text += fmt.Sprintf("\nstatus: STALE (no successful poll within %s)", status.StalenessWindow)
	default:
		text += "\nstatus: FAILING"
	}
	return textToolResult(text)
}

func handleWaiversList(api API, input projectInput) (*mcp.CallToolResult, any, error) {
	if input.Project == "" {
		return nil, nil, fmt.Errorf("project is required")
	}
	waivers, err := api.ListWaivers(input.Project)
	if err != nil {
		return nil, nil, err
	}
	if len(waivers) == 0 {
		return textToolResult("No waivers found.")
	}
	var text strings.Builder
	fmt.Fprintf(&text, "Found %d waiver(s):\n", len(waivers))
	for _, waiver := range waivers {
		status := "enabled"
		if !waiver.Enabled {
			status = "disabled"
		}
		fmt.Fprintf(&text, "- %s [%s] %s\n", waiver.ID, status, waiver.Name)
	}
	return textToolResult(text.String())
}

func handleWaiversGet(api API, input waiverInput) (*mcp.CallToolResult, any, error) {
	if input.Project == "" || input.WaiverID == "" {
		return nil, nil, fmt.Errorf("project and waiver_id are required")
	}
	waiver, err := api.GetWaiver(input.Project, input.WaiverID)
	if err != nil {
		return nil, nil, err
	}
	status := "enabled"
	if !waiver.Enabled {
		status = "disabled"
	}
	return textToolResult(fmt.Sprintf("Waiver: %s\nName: %s\nDescription: %s\nStatus: %s\nConditions: %d\nContexts: %d\nTargets: %d", waiver.ID, waiver.Name, waiver.Description, status, len(waiver.Conditions), len(waiver.Contexts), len(waiver.Targets)))
}

func handleWaiversCreate(api API, input waiverCreateInput) (*mcp.CallToolResult, any, error) {
	if input.Project == "" || input.Name == "" {
		return nil, nil, fmt.Errorf("project and name are required")
	}
	waiver, err := api.CreateWaiver(input.Project, &client.CreateWaiverRequest{
		Name:        input.Name,
		Description: input.Description,
		ExpiresAt:   input.ExpiresAt,
		TargetIDs:   input.FindingIDs,
	})
	if err != nil {
		return nil, nil, err
	}
	return textToolResult(fmt.Sprintf("Waiver created: %s (%s)", waiver.ID, waiver.Name))
}

func handleWaiversToggle(api API, input waiverInput) (*mcp.CallToolResult, any, error) {
	if input.Project == "" || input.WaiverID == "" {
		return nil, nil, fmt.Errorf("project and waiver_id are required")
	}
	waiver, err := api.ToggleWaiver(input.Project, input.WaiverID)
	if err != nil {
		return nil, nil, err
	}
	status := "enabled"
	if !waiver.Enabled {
		status = "disabled"
	}
	return textToolResult(fmt.Sprintf("Waiver %s is now %s", waiver.ID, status))
}

func handleWaiverEvents(api API, input waiverInput) (*mcp.CallToolResult, any, error) {
	if input.Project == "" || input.WaiverID == "" {
		return nil, nil, fmt.Errorf("project and waiver_id are required")
	}
	events, err := api.ListWaiverEvents(input.Project, input.WaiverID)
	if err != nil {
		return nil, nil, err
	}
	var text strings.Builder
	fmt.Fprintf(&text, "Found %d event(s):\n", len(events))
	for _, event := range events {
		fmt.Fprintf(&text, "- %s: %s (%s)\n", event.ID, event.EventType, event.CreatedAt)
	}
	return textToolResult(text.String())
}
