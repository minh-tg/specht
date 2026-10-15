package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// callTool runs one tool through a real MCP session and returns its text and whether it failed.
func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatal(err)
	}
	return result.Content[0].(*mcp.TextContent).Text, result.IsError
}

func mustContain(t *testing.T, text string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("output %q does not contain %q", text, want)
		}
	}
}

func TestMCPProjectTools(t *testing.T) {
	desc := "Card processing"
	mc := &mockClient{
		projects: []client.Project{{Slug: "payments", Name: "Payments", Description: &desc, Role: "manager"}},
		stats: &client.ProjectStats{
			TotalFindings: 7, BlockingCount: 2, WaiverCount: 1, PendingWaiverCount: 3, ReportCount: 4,
			BySeverity:      []client.SeverityCount{{Severity: "high", Count: 2, BlockingCount: 2}},
			ByAnalysisState: []client.AnalysisStateCount{{State: "in_triage", Count: 5}},
		},
		aging: &client.AgingResponse{
			OverdueTotal: 1, Reopened: 2,
			Buckets: []client.AgingBucketCount{{Bucket: "0-7d", Count: 3, Overdue: 0}},
			Overdue: []client.OverdueFinding{{ID: "f9", Title: "Old bug", Severity: "high", AgeDays: 40, SLADays: 30}},
		},
	}
	session := connectMCPServer(t, mc)

	text, failed := callTool(t, session, "projects_list", map[string]any{})
	if failed {
		t.Fatal(text)
	}
	mustContain(t, text, "payments", "Payments")

	text, _ = callTool(t, session, "project_get", map[string]any{"project": "payments"})
	mustContain(t, text, "Payments", "Card processing", "manager")

	text, _ = callTool(t, session, "project_stats", map[string]any{"project": "payments"})
	mustContain(t, text, "7 finding", "2 blocking", "3 waiver request", "high: 2", "in_triage: 5")

	text, _ = callTool(t, session, "project_aging", map[string]any{"project": "payments"})
	mustContain(t, text, "1 overdue", "f9", "40 days", "SLA 30", "2 reopened")

	for _, tool := range []string{"project_get", "project_stats", "project_aging"} {
		if text, failed := callTool(t, session, tool, map[string]any{}); !failed || !strings.Contains(text, "project") {
			t.Errorf("%s without a project: failed=%v text=%q", tool, failed, text)
		}
	}
}

func TestMCPInventoryTools(t *testing.T) {
	sha := "abc1234"
	count := int32(3)
	mc := &mockClient{
		reports:      []client.Report{{ID: "r1", ToolName: "trivy", ScanType: "sca", Status: "completed", TotalFindings: &count, CommitSha: &sha}},
		environments: []client.Environment{{ID: "e1", Name: "production", Tier: "prod", InternetFacing: true, DataSensitivity: "restricted"}},
		targets:      []client.Target{{ID: "t1", Name: "api", Kind: "repository"}},
		artifacts:    []client.Artifact{{ID: "a1", Name: "api", ArtifactType: "container_image", Version: "1.2.0"}},
	}
	session := connectMCPServer(t, mc)

	text, _ := callTool(t, session, "reports_list", map[string]any{"project": "payments"})
	mustContain(t, text, "r1", "trivy", "3 finding", "abc1234")

	text, _ = callTool(t, session, "report_get", map[string]any{"report_id": "r1"})
	mustContain(t, text, "r1", "trivy", "sca", "completed")

	text, _ = callTool(t, session, "environments_list", map[string]any{"project": "payments"})
	mustContain(t, text, "production", "prod", "internet facing", "restricted")

	text, _ = callTool(t, session, "targets_list", map[string]any{"project": "payments"})
	mustContain(t, text, "api", "repository")

	text, _ = callTool(t, session, "artifacts_list", map[string]any{"project": "payments"})
	mustContain(t, text, "api", "container_image", "1.2.0")

	if text, failed := callTool(t, session, "report_get", map[string]any{}); !failed || !strings.Contains(text, "report_id") {
		t.Errorf("report_get without an ID: failed=%v text=%q", failed, text)
	}
	empty := connectMCPServer(t, &mockClient{})
	text, _ = callTool(t, empty, "environments_list", map[string]any{"project": "payments"})
	mustContain(t, text, "No environments")
}

func TestMCPFindingEventsForwardsFilters(t *testing.T) {
	comment := "test fixture"
	mc := &mockClient{findingEvents: []client.FindingEvent{{EventType: "analysis_changed", UserName: "Ada", Comment: &comment}}}
	session := connectMCPServer(t, mc)

	text, failed := callTool(t, session, "finding_events", map[string]any{"finding_id": "f1", "types": "analysis_changed, comment", "limit": 5})
	if failed {
		t.Fatal(text)
	}
	mustContain(t, text, "analysis_changed", "Ada", "test fixture")
	if got := strings.Join(mc.eventTypes, "|"); got != "analysis_changed|comment" {
		t.Errorf("event types = %q, want them split and trimmed", got)
	}
	if mc.eventLimit != 5 {
		t.Errorf("limit = %d, want 5", mc.eventLimit)
	}
	if _, failed := callTool(t, session, "finding_events", map[string]any{}); !failed {
		t.Error("finding_events without a finding_id must fail")
	}
}

func TestMCPScannersListIsASessionTool(t *testing.T) {
	mc := &mockClient{scanners: []client.ScannerDescriptor{{
		Name: "semgrep", DisplayName: "Semgrep",
		Formats: []client.ScannerFormat{{Name: "SARIF", Extensions: []string{".sarif"}, Command: "semgrep scan --sarif"}},
	}}}
	text, failed := callTool(t, connectMCPServer(t, mc), "scanners_list", map[string]any{})
	if failed {
		t.Fatal(text)
	}
	mustContain(t, text, "semgrep", "Semgrep", "semgrep scan --sarif", ".sarif")

	if listedTools(t, toolOptions{})["scanners_list"] {
		t.Error("a project key cannot call the scanners route, so the tool must not be offered")
	}
}

func TestMCPFindingsTriage(t *testing.T) {
	mc := &mockClient{triageResp: &client.TriageResponse{FindingID: "f1", AnalysisState: "false_positive", GateEffect: "ignore"}}
	session := connectMCPServer(t, mc)

	text, failed := callTool(t, session, "findings_triage", map[string]any{
		"finding_id": "f1", "state": "false_positive", "reason": "test fixture", "expires_at": "2030-01-02T03:04:05Z",
	})
	if failed {
		t.Fatal(text)
	}
	mustContain(t, text, "f1", "false_positive", "gate: ignore")
	want := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	if mc.triageID != "f1" || mc.triageReq == nil || mc.triageReq.AnalysisState != "false_positive" ||
		mc.triageReq.Reason != "test fixture" || mc.triageReq.AnalysisExpiresAt == nil || !mc.triageReq.AnalysisExpiresAt.Equal(want) {
		t.Fatalf("request not forwarded: id=%q req=%+v", mc.triageID, mc.triageReq)
	}

	mc.triageReq = nil
	for name, args := range map[string]map[string]any{
		"no finding":  {"state": "exploitable"},
		"no state":    {"finding_id": "f1"},
		"bad expires": {"finding_id": "f1", "state": "false_positive", "expires_at": "next week"},
	} {
		if text, failed := callTool(t, session, "findings_triage", args); !failed {
			t.Errorf("%s: expected an error, got %q", name, text)
		}
	}
	if mc.triageReq != nil {
		t.Errorf("a refused call must not reach the API: %+v", mc.triageReq)
	}
}

func TestMCPWaiverRequestAndWithdraw(t *testing.T) {
	mc := &mockClient{waiver: &client.Waiver{ID: "w1", Name: "pending"}}
	session := connectMCPServer(t, mc)

	text, failed := callTool(t, session, "waivers_request", map[string]any{
		"project": "payments", "finding_ids": []string{"f1", "f2"}, "reason": "no fix upstream", "expires_at": "2030-01-02T03:04:05Z",
	})
	if failed {
		t.Fatal(text)
	}
	mustContain(t, text, "w1", "waiting for a decision")
	req := mc.requestedWaiver
	if req == nil || len(req.TargetIDs) != 2 || req.TargetIDs[1] != "f2" || req.Reason != "no fix upstream" || req.ExpiresAt != "2030-01-02T03:04:05Z" {
		t.Fatalf("request not forwarded: %+v", req)
	}

	mc.requestedWaiver = nil
	for name, args := range map[string]map[string]any{
		"no project":  {"finding_ids": []string{"f1"}, "reason": "r", "expires_at": "2030-01-02T03:04:05Z"},
		"no findings": {"project": "payments", "reason": "r", "expires_at": "2030-01-02T03:04:05Z"},
		"no reason":   {"project": "payments", "finding_ids": []string{"f1"}, "expires_at": "2030-01-02T03:04:05Z"},
		"no expiry":   {"project": "payments", "finding_ids": []string{"f1"}, "reason": "r"},
	} {
		if text, failed := callTool(t, session, "waivers_request", args); !failed {
			t.Errorf("%s: expected an error, got %q", name, text)
		}
	}
	if mc.requestedWaiver != nil {
		t.Errorf("a refused call must not reach the API: %+v", mc.requestedWaiver)
	}

	text, failed = callTool(t, session, "waivers_withdraw", map[string]any{"project": "payments", "waiver_id": "w1"})
	if failed {
		t.Fatal(text)
	}
	if mc.withdrawn != "w1" {
		t.Errorf("withdrawn = %q, want w1", mc.withdrawn)
	}
}

// Approving a waiver is the human half of a request. The bridge offers no tool for it.
func TestMCPOffersNoWaiverDecision(t *testing.T) {
	for name := range listedTools(t, fullTools) {
		if strings.Contains(name, "approve") || strings.Contains(name, "reject") {
			t.Errorf("tool %q lets an assistant decide a waiver request", name)
		}
	}
}

func TestMCPEnvironmentsUpdateChangesOnlyWhatIsGiven(t *testing.T) {
	mc := &mockClient{environments: []client.Environment{
		{ID: "e1", Name: "production", Tier: "production", InternetFacing: true, DataSensitivity: "restricted"},
		{ID: "e2", Name: "staging", Tier: "staging", DataSensitivity: "internal"},
	}}
	session := connectMCPServer(t, mc)

	text, failed := callTool(t, session, "environments_update", map[string]any{"project": "payments", "environment": "production", "data_sensitivity": "confidential"})
	if failed {
		t.Fatal(text)
	}
	mustContain(t, text, "production", "confidential", "internet facing")
	want := client.EnvironmentSettings{Tier: "production", InternetFacing: true, DataSensitivity: "confidential"}
	if mc.envID != "e1" || mc.envSettings == nil || *mc.envSettings != want {
		t.Fatalf("settings = %+v for %q, want %+v for e1", mc.envSettings, mc.envID, want)
	}

	// An explicit false turns exposure off; naming the environment by ID works too.
	if text, failed = callTool(t, session, "environments_update", map[string]any{"project": "payments", "environment": "e1", "internet_facing": false}); failed {
		t.Fatal(text)
	}
	if mc.envSettings.InternetFacing {
		t.Errorf("internet_facing=false was not forwarded: %+v", mc.envSettings)
	}
}

func TestMCPEnvironmentsUpdateRefusesBeforeTheAPI(t *testing.T) {
	mc := &mockClient{environments: []client.Environment{{ID: "e1", Name: "production", Tier: "production"}}}
	session := connectMCPServer(t, mc)
	for name, args := range map[string]map[string]any{
		"no project":     {"environment": "production", "tier": "test"},
		"no environment": {"project": "payments", "tier": "test"},
		"nothing to set": {"project": "payments", "environment": "production"},
		"unknown name":   {"project": "payments", "environment": "nowhere", "tier": "test"},
	} {
		if text, failed := callTool(t, session, "environments_update", args); !failed {
			t.Errorf("%s: expected an error, got %q", name, text)
		}
	}
	if mc.envSettings != nil {
		t.Errorf("a refused call must not reach the API: %+v", mc.envSettings)
	}
}

// A limit too large for the API's 32-bit page size is refused, not wrapped to a small number.
func TestMCPRefusesALimitThatWouldWrap(t *testing.T) {
	mc := &mockClient{}
	session := connectMCPServer(t, mc)
	for tool, args := range map[string]map[string]any{
		"findings_list":  {"project": "payments", "limit": 4294967297},
		"reports_list":   {"project": "payments", "limit": 4294967297},
		"finding_events": {"finding_id": "f1", "limit": 4294967297},
	} {
		text, failed := callTool(t, session, tool, args)
		if !failed || !strings.Contains(text, "limit") {
			t.Errorf("%s: failed=%v text=%q, want a limit error", tool, failed, text)
		}
	}
	if mc.eventLimit != 0 {
		t.Errorf("the request must not reach the API, limit = %d", mc.eventLimit)
	}
}
