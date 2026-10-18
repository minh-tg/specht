package main

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/minh-tg/specht/internal/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type reportInput struct {
	ReportID string `json:"report_id" jsonschema:"report ID"`
}

type reportsListInput struct {
	Project string `json:"project" jsonschema:"project slug"`
	Limit   int    `json:"limit,omitempty" jsonschema:"maximum number of reports, newest first"`
}

type findingEventsInput struct {
	FindingID string `json:"finding_id" jsonschema:"finding ID"`
	Types     string `json:"types,omitempty" jsonschema:"comma-separated event types to keep"`
	Limit     int    `json:"limit,omitempty" jsonschema:"maximum number of events"`
}

type triageInput struct {
	FindingID string `json:"finding_id" jsonschema:"finding ID"`
	State     string `json:"state" jsonschema:"analysis state, such as in_triage, exploitable, false_positive or not_affected"`
	Reason    string `json:"reason,omitempty" jsonschema:"why; required for a state that stops the finding blocking the gate"`
	ExpiresAt string `json:"expires_at,omitempty" jsonschema:"RFC3339 time when the decision lapses"`
}

type waiverRequestInput struct {
	Project    string   `json:"project" jsonschema:"project slug"`
	FindingIDs []string `json:"finding_ids" jsonschema:"findings the waiver would cover"`
	Reason     string   `json:"reason" jsonschema:"why the findings should be waived"`
	ExpiresAt  string   `json:"expires_at" jsonschema:"RFC3339 expiry, in the future and at most 90 days ahead"`
}

// registerInventoryTools adds the read-only project, report and history tools.
func registerInventoryTools(server *mcp.Server, api API) {
	addTool(server, &mcp.Tool{Name: "projects_list", Description: "List the projects this credential can see"}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return handleProjectsList(api)
	})
	addTool(server, &mcp.Tool{Name: "project_get", Description: "Show a project, and the caller's role in it"}, func(_ context.Context, _ *mcp.CallToolRequest, input projectInput) (*mcp.CallToolResult, any, error) {
		return handleProjectGet(api, input)
	})
	addTool(server, &mcp.Tool{Name: "project_stats", Description: "Count a project's findings by severity and analysis state, with blocking findings and pending waiver requests"}, func(_ context.Context, _ *mcp.CallToolRequest, input projectInput) (*mcp.CallToolResult, any, error) {
		return handleProjectStats(api, input)
	})
	addTool(server, &mcp.Tool{Name: "project_aging", Description: "Show how long a project's open findings have been open and which are past their SLA"}, func(_ context.Context, _ *mcp.CallToolRequest, input projectInput) (*mcp.CallToolResult, any, error) {
		return handleProjectAging(api, input)
	})
	addTool(server, &mcp.Tool{Name: "reports_list", Description: "List a project's uploaded reports, newest first"}, func(_ context.Context, _ *mcp.CallToolRequest, input reportsListInput) (*mcp.CallToolResult, any, error) {
		return handleReportsList(api, input)
	})
	addTool(server, &mcp.Tool{Name: "report_get", Description: "Show one uploaded report"}, func(_ context.Context, _ *mcp.CallToolRequest, input reportInput) (*mcp.CallToolResult, any, error) {
		return handleReportGet(api, input)
	})
	addTool(server, &mcp.Tool{Name: "environments_list", Description: "List a project's environments with their tier, exposure and data sensitivity"}, func(_ context.Context, _ *mcp.CallToolRequest, input projectInput) (*mcp.CallToolResult, any, error) {
		return handleEnvironmentsList(api, input)
	})
	addTool(server, &mcp.Tool{Name: "targets_list", Description: "List what a project's scans were run against"}, func(_ context.Context, _ *mcp.CallToolRequest, input projectInput) (*mcp.CallToolResult, any, error) {
		return handleTargetsList(api, input)
	})
	addTool(server, &mcp.Tool{Name: "artifacts_list", Description: "List the images, packages and other artifacts a project's scans found"}, func(_ context.Context, _ *mcp.CallToolRequest, input projectInput) (*mcp.CallToolResult, any, error) {
		return handleArtifactsList(api, input)
	})
	addTool(server, &mcp.Tool{Name: "finding_events", Description: "Show a finding's history: who decided what, and when"}, func(_ context.Context, _ *mcp.CallToolRequest, input findingEventsInput) (*mcp.CallToolResult, any, error) {
		return handleFindingEvents(api, input)
	})
}

// registerSessionInventoryTools adds the read tools whose routes reject API keys.
func registerSessionInventoryTools(server *mcp.Server, api API) {
	addTool(server, &mcp.Tool{Name: "scanners_list", Description: "List the scanners Specht reads, the file formats each accepts and the command that produces them"}, func(_ context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		return handleScannersList(api)
	})
}

type environmentUpdateInput struct {
	Project         string `json:"project" jsonschema:"project slug"`
	Environment     string `json:"environment" jsonschema:"environment name or ID"`
	Tier            string `json:"tier,omitempty" jsonschema:"production, staging, development or test"`
	InternetFacing  *bool  `json:"internet_facing,omitempty" jsonschema:"whether it can be reached from the internet"`
	DataSensitivity string `json:"data_sensitivity,omitempty" jsonschema:"public, internal, confidential or restricted"`
}

// registerTriageTools adds the tools that decide findings and ask for waivers. Approving or
// rejecting a waiver request is left out on purpose: that is the second person's decision.
func registerTriageTools(server *mcp.Server, api API) {
	addTool(server, &mcp.Tool{Name: "findings_triage", Description: "Record an analysis decision on a finding. A state such as false_positive or not_affected stops it blocking the gate, so only use it on a person's say-so. Needs the project admin role."}, func(_ context.Context, _ *mcp.CallToolRequest, input triageInput) (*mcp.CallToolResult, any, error) {
		return handleFindingsTriage(api, input)
	})
	addTool(server, &mcp.Tool{Name: "waivers_request", Description: "Ask for a waiver on specific findings. It waits for a project manager or admin to approve it."}, func(_ context.Context, _ *mcp.CallToolRequest, input waiverRequestInput) (*mcp.CallToolResult, any, error) {
		return handleWaiversRequest(api, input)
	})
	addTool(server, &mcp.Tool{Name: "environments_update", Description: "Change an environment's tier, internet exposure or data sensitivity. These feed the risk score, so only change them on a person's say-so. Needs the project admin role."}, func(_ context.Context, _ *mcp.CallToolRequest, input environmentUpdateInput) (*mcp.CallToolResult, any, error) {
		return handleEnvironmentsUpdate(api, input)
	})
	addTool(server, &mcp.Tool{Name: "waivers_withdraw", Description: "Withdraw a waiver request that has not been decided"}, func(_ context.Context, _ *mcp.CallToolRequest, input waiverInput) (*mcp.CallToolResult, any, error) {
		return handleWaiversWithdraw(api, input)
	})
}

// pageSize turns a tool's limit into the int32 page size the API takes. A missing or non-positive
// limit means def. A value that does not fit is refused, because a bare int32 conversion would
// wrap it to some small number.
func pageSize(limit int, def int32) (int32, error) {
	if limit <= 0 {
		return def, nil
	}
	if limit > math.MaxInt32 {
		return 0, fmt.Errorf("limit must be at most %d", math.MaxInt32)
	}
	return int32(limit), nil
}

func requireProject(project string) error {
	if project == "" {
		return fmt.Errorf("project is required")
	}
	return nil
}

func handleProjectsList(api API) (*mcp.CallToolResult, any, error) {
	projects, err := api.ListProjects()
	if err != nil {
		return nil, nil, err
	}
	if len(projects) == 0 {
		return textToolResult("No projects.")
	}
	var text strings.Builder
	fmt.Fprintf(&text, "%d project(s):\n", len(projects))
	for _, p := range projects {
		fmt.Fprintf(&text, "- %s (%s)\n", p.Slug, p.Name)
	}
	return textToolResult(strings.TrimSpace(text.String()))
}

func handleProjectGet(api API, input projectInput) (*mcp.CallToolResult, any, error) {
	if err := requireProject(input.Project); err != nil {
		return nil, nil, err
	}
	p, err := api.GetProject(input.Project)
	if err != nil {
		return nil, nil, err
	}
	text := fmt.Sprintf("Project: %s (%s)", p.Slug, p.Name)
	if p.Description != nil && *p.Description != "" {
		text += "\nDescription: " + *p.Description
	}
	if p.Role != "" {
		text += "\nYour role: " + p.Role
	}
	return textToolResult(text)
}

func handleProjectStats(api API, input projectInput) (*mcp.CallToolResult, any, error) {
	if err := requireProject(input.Project); err != nil {
		return nil, nil, err
	}
	s, err := api.GetProjectStats(input.Project)
	if err != nil {
		return nil, nil, err
	}
	var text strings.Builder
	fmt.Fprintf(&text, "%d finding(s), %d blocking; %d waiver(s), %d waiver request(s) pending; %d report(s)", s.TotalFindings, s.BlockingCount, s.WaiverCount, s.PendingWaiverCount, s.ReportCount)
	if len(s.BySeverity) > 0 {
		text.WriteString("\nBy severity:")
		for _, c := range s.BySeverity {
			fmt.Fprintf(&text, "\n  %s: %d (%d blocking)", c.Severity, c.Count, c.BlockingCount)
		}
	}
	if len(s.ByAnalysisState) > 0 {
		text.WriteString("\nBy analysis state:")
		for _, c := range s.ByAnalysisState {
			fmt.Fprintf(&text, "\n  %s: %d", c.State, c.Count)
		}
	}
	return textToolResult(text.String())
}

func handleProjectAging(api API, input projectInput) (*mcp.CallToolResult, any, error) {
	if err := requireProject(input.Project); err != nil {
		return nil, nil, err
	}
	a, err := api.GetAging(input.Project)
	if err != nil {
		return nil, nil, err
	}
	var text strings.Builder
	fmt.Fprintf(&text, "%d overdue finding(s), %d reopened", a.OverdueTotal, a.Reopened)
	for _, b := range a.Buckets {
		fmt.Fprintf(&text, "\n  %s: %d (%d overdue)", b.Bucket, b.Count, b.Overdue)
	}
	for _, f := range a.Overdue {
		fmt.Fprintf(&text, "\n  overdue: %s [%s] %s, %d days old, SLA %d", f.ID, f.Severity, f.Title, f.AgeDays, f.SLADays)
	}
	if a.Truncated {
		text.WriteString("\n(the project has more open findings than this report covers; these are the oldest)")
	}
	return textToolResult(text.String())
}

func handleReportsList(api API, input reportsListInput) (*mcp.CallToolResult, any, error) {
	if err := requireProject(input.Project); err != nil {
		return nil, nil, err
	}
	limit, err := pageSize(input.Limit, 20)
	if err != nil {
		return nil, nil, err
	}
	reports, err := api.ListReports(input.Project, limit, 0)
	if err != nil {
		return nil, nil, err
	}
	if len(reports) == 0 {
		return textToolResult("No reports.")
	}
	var text strings.Builder
	fmt.Fprintf(&text, "%d report(s):\n", len(reports))
	for _, r := range reports {
		fmt.Fprintf(&text, "- %s %s (%s) %s", r.ID, r.ToolName, r.ScanType, r.Status)
		if r.TotalFindings != nil {
			fmt.Fprintf(&text, ", %d finding(s)", *r.TotalFindings)
		}
		if r.CommitSha != nil && *r.CommitSha != "" {
			fmt.Fprintf(&text, ", commit %s", *r.CommitSha)
		}
		text.WriteString("\n")
	}
	return textToolResult(strings.TrimSpace(text.String()))
}

func handleReportGet(api API, input reportInput) (*mcp.CallToolResult, any, error) {
	if input.ReportID == "" {
		return nil, nil, fmt.Errorf("report_id is required")
	}
	r, err := api.GetReport(input.ReportID)
	if err != nil {
		return nil, nil, err
	}
	text := fmt.Sprintf("Report: %s\nTool: %s\nScan type: %s\nStatus: %s\nCreated: %s", r.ID, r.ToolName, r.ScanType, r.Status, r.CreatedAt.Format(time.RFC3339))
	if r.TotalFindings != nil {
		text += fmt.Sprintf("\nFindings: %d", *r.TotalFindings)
	}
	if r.Branch != nil && *r.Branch != "" {
		text += "\nBranch: " + *r.Branch
	}
	if r.CommitSha != nil && *r.CommitSha != "" {
		text += "\nCommit: " + *r.CommitSha
	}
	if r.ScanTarget != nil && *r.ScanTarget != "" {
		text += "\nTarget: " + *r.ScanTarget
	}
	return textToolResult(text)
}

func handleEnvironmentsList(api API, input projectInput) (*mcp.CallToolResult, any, error) {
	if err := requireProject(input.Project); err != nil {
		return nil, nil, err
	}
	envs, err := api.ListEnvironments(input.Project)
	if err != nil {
		return nil, nil, err
	}
	if len(envs) == 0 {
		return textToolResult("No environments.")
	}
	var text strings.Builder
	for _, e := range envs {
		exposure := "internal"
		if e.InternetFacing {
			exposure = "internet facing"
		}
		fmt.Fprintf(&text, "- %s: tier %s, %s, data %s\n", e.Name, e.Tier, exposure, e.DataSensitivity)
	}
	return textToolResult(strings.TrimSpace(text.String()))
}

func handleTargetsList(api API, input projectInput) (*mcp.CallToolResult, any, error) {
	if err := requireProject(input.Project); err != nil {
		return nil, nil, err
	}
	targets, err := api.ListTargets(input.Project)
	if err != nil {
		return nil, nil, err
	}
	if len(targets) == 0 {
		return textToolResult("No targets.")
	}
	var text strings.Builder
	for _, t := range targets {
		fmt.Fprintf(&text, "- %s (%s) %s\n", t.Name, t.Kind, t.Locator)
	}
	return textToolResult(strings.TrimSpace(text.String()))
}

func handleArtifactsList(api API, input projectInput) (*mcp.CallToolResult, any, error) {
	if err := requireProject(input.Project); err != nil {
		return nil, nil, err
	}
	artifacts, err := api.ListArtifacts(input.Project)
	if err != nil {
		return nil, nil, err
	}
	if len(artifacts) == 0 {
		return textToolResult("No artifacts.")
	}
	var text strings.Builder
	for _, a := range artifacts {
		fmt.Fprintf(&text, "- %s (%s) %s\n", a.Name, a.ArtifactType, a.Version)
	}
	return textToolResult(strings.TrimSpace(text.String()))
}

func handleFindingEvents(api API, input findingEventsInput) (*mcp.CallToolResult, any, error) {
	if input.FindingID == "" {
		return nil, nil, fmt.Errorf("finding_id is required")
	}
	var types []string
	for _, kind := range strings.Split(input.Types, ",") {
		if kind = strings.TrimSpace(kind); kind != "" {
			types = append(types, kind)
		}
	}
	limit, err := pageSize(input.Limit, 50)
	if err != nil {
		return nil, nil, err
	}
	events, err := api.ListFindingEvents(input.FindingID, types, limit, 0)
	if err != nil {
		return nil, nil, err
	}
	if len(events) == 0 {
		return textToolResult("No events.")
	}
	var text strings.Builder
	for _, e := range events {
		who := e.UserName
		if who == "" {
			who = e.UserID
		}
		fmt.Fprintf(&text, "- %s %s by %s", e.CreatedAt.Format(time.RFC3339), e.EventType, who)
		if e.OldValue != nil || e.NewValue != nil {
			fmt.Fprintf(&text, ": %s -> %s", deref(e.OldValue), deref(e.NewValue))
		}
		if e.Comment != nil && *e.Comment != "" {
			fmt.Fprintf(&text, " (%s)", *e.Comment)
		}
		text.WriteString("\n")
	}
	return textToolResult(strings.TrimSpace(text.String()))
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func handleScannersList(api API) (*mcp.CallToolResult, any, error) {
	scanners, err := api.ListScanners()
	if err != nil {
		return nil, nil, err
	}
	var text strings.Builder
	for _, s := range scanners {
		fmt.Fprintf(&text, "- %s (%s)\n", s.Name, s.DisplayName)
		for _, f := range s.Formats {
			fmt.Fprintf(&text, "    %s %s: %s\n", f.Name, strings.Join(f.Extensions, ", "), f.Command)
		}
	}
	return textToolResult(strings.TrimSpace(text.String()))
}

func handleFindingsTriage(api API, input triageInput) (*mcp.CallToolResult, any, error) {
	if input.FindingID == "" || input.State == "" {
		return nil, nil, fmt.Errorf("finding_id and state are required")
	}
	req := &client.TriageRequest{AnalysisState: input.State, Reason: input.Reason}
	if input.ExpiresAt != "" {
		at, err := time.Parse(time.RFC3339, input.ExpiresAt)
		if err != nil {
			return nil, nil, fmt.Errorf("expires_at must be an RFC3339 time such as 2030-01-02T03:04:05Z: %w", err)
		}
		req.AnalysisExpiresAt = &at
	}
	resp, err := api.TriageFinding(input.FindingID, req)
	if err != nil {
		return nil, nil, err
	}
	return textToolResult(fmt.Sprintf("finding %s is now %s (gate: %s)", resp.FindingID, resp.AnalysisState, resp.GateEffect))
}

func handleWaiversRequest(api API, input waiverRequestInput) (*mcp.CallToolResult, any, error) {
	switch {
	case input.Project == "":
		return nil, nil, fmt.Errorf("project is required")
	case len(input.FindingIDs) == 0:
		return nil, nil, fmt.Errorf("finding_ids is required: a waiver has to name what it covers")
	case input.Reason == "":
		return nil, nil, fmt.Errorf("reason is required")
	case input.ExpiresAt == "":
		return nil, nil, fmt.Errorf("expires_at is required: a waiver request cannot be open-ended")
	}
	waiver, err := api.RequestWaiver(input.Project, &client.RequestWaiverRequest{TargetIDs: input.FindingIDs, Reason: input.Reason, ExpiresAt: input.ExpiresAt})
	if err != nil {
		return nil, nil, err
	}
	return textToolResult(fmt.Sprintf("waiver request %s is waiting for a decision from a project manager or admin", waiver.ID))
}

func handleWaiversWithdraw(api API, input waiverInput) (*mcp.CallToolResult, any, error) {
	if input.Project == "" || input.WaiverID == "" {
		return nil, nil, fmt.Errorf("project and waiver_id are required")
	}
	waiver, err := api.WithdrawWaiver(input.Project, input.WaiverID)
	if err != nil {
		return nil, nil, err
	}
	return textToolResult(fmt.Sprintf("waiver request %s withdrawn", waiver.ID))
}

func handleEnvironmentsUpdate(api API, input environmentUpdateInput) (*mcp.CallToolResult, any, error) {
	switch {
	case input.Project == "":
		return nil, nil, fmt.Errorf("project is required")
	case input.Environment == "":
		return nil, nil, fmt.Errorf("environment is required")
	case input.Tier == "" && input.InternetFacing == nil && input.DataSensitivity == "":
		return nil, nil, fmt.Errorf("nothing to change: give tier, internet_facing or data_sensitivity")
	}
	envs, err := api.ListEnvironments(input.Project)
	if err != nil {
		return nil, nil, err
	}
	var current *client.Environment
	for i := range envs {
		if envs[i].ID == input.Environment || envs[i].Name == input.Environment {
			current = &envs[i]
			break
		}
	}
	if current == nil {
		return nil, nil, fmt.Errorf("no environment %q in project %s (environments_list shows them)", input.Environment, input.Project)
	}
	settings := client.EnvironmentSettings{Tier: current.Tier, InternetFacing: current.InternetFacing, DataSensitivity: current.DataSensitivity}
	if input.Tier != "" {
		settings.Tier = input.Tier
	}
	if input.InternetFacing != nil {
		settings.InternetFacing = *input.InternetFacing
	}
	if input.DataSensitivity != "" {
		settings.DataSensitivity = input.DataSensitivity
	}
	updated, err := api.UpdateEnvironment(input.Project, current.ID, settings)
	if err != nil {
		return nil, nil, err
	}
	exposure := "internal"
	if updated.InternetFacing {
		exposure = "internet facing"
	}
	return textToolResult(fmt.Sprintf("environment %s: tier %s, %s, data %s", updated.Name, updated.Tier, exposure, updated.DataSensitivity))
}
