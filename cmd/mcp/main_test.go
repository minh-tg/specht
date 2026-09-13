package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/client"
)

type mockClient struct {
	client.Client
	findings         []client.Finding
	gate             *client.GateStatus
	waivers          []client.Waiver
	waiver           *client.Waiver
	waiverDet        *client.WaiverDetail
	events           []client.WaiverEvent
	assessment       *client.ReachabilityAssessment
	watcher          *client.WatcherStatus
	preview          *client.PRCheckPreview
	patch            *client.PatchOutcome
	introducedReport string
	err              error
}

func (m *mockClient) ListFindings(projectSlug string, severities, states []string, limit, offset int32) ([]client.Finding, error) {
	return m.findings, m.err
}

func (m *mockClient) GetFinding(findingID string) (*client.Finding, error) {
	if len(m.findings) > 0 {
		return &m.findings[0], m.err
	}
	return nil, m.err
}

func (m *mockClient) GetGateStatus(projectSlug string, severity string) (*client.GateStatus, error) {
	return m.gate, m.err
}

func (m *mockClient) GetIntroducedGateStatus(projectSlug string, severity string, reportID string) (*client.GateStatus, error) {
	m.introducedReport = reportID
	return m.gate, m.err
}

func (m *mockClient) PreviewPRCheck(projectSlug string, commit string, provider string, reportID string, severity string) (*client.PRCheckPreview, error) {
	return m.preview, m.err
}

func (m *mockClient) PreviewPatch(findingID string) (*client.PatchOutcome, error) {
	return m.patch, m.err
}

func (m *mockClient) UpsertReachability(findingID, state, evidence string) (*client.ReachabilityAssessment, error) {
	if m.assessment == nil {
		return nil, m.err
	}
	return m.assessment, m.err
}

func (m *mockClient) ListReachability(findingID string) ([]client.ReachabilityAssessment, error) {
	if m.assessment == nil {
		return nil, m.err
	}
	return []client.ReachabilityAssessment{*m.assessment}, m.err
}

func (m *mockClient) GetWatcherStatus() (*client.WatcherStatus, error) {
	return m.watcher, m.err
}

func (m *mockClient) ListWaivers(projectSlug string) ([]client.Waiver, error) {
	return m.waivers, m.err
}

func (m *mockClient) GetWaiver(projectSlug, waiverID string) (*client.WaiverDetail, error) {
	return m.waiverDet, m.err
}

func (m *mockClient) CreateWaiver(projectSlug string, req *client.CreateWaiverRequest) (*client.Waiver, error) {
	return m.waiver, m.err
}

func (m *mockClient) ToggleWaiver(projectSlug, waiverID string) (*client.Waiver, error) {
	return m.waiver, m.err
}

func (m *mockClient) ListWaiverEvents(projectSlug, waiverID string) ([]client.WaiverEvent, error) {
	return m.events, m.err
}

func TestJSONRPCParse(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`
	msg, err := parseMessage([]byte(raw))
	require.NoError(t, err)
	assert.Equal(t, "2.0", msg.JSONRPC)
	assert.Equal(t, float64(1), msg.ID)
	assert.Equal(t, "initialize", msg.Method)
}

func TestMCPInitialize(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(&mockClient{}, req)
	assert.Equal(t, float64(1), resp.ID)
	require.NotNil(t, resp.Result)
	var init InitResult
	err := json.Unmarshal(*resp.Result, &init)
	require.NoError(t, err)
	assert.Equal(t, "2024-11-05", init.ProtocolVersion)
	assert.Contains(t, init.ServerInfo.Name, "specht-mcp")
}

func TestMCPToolsList(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(&mockClient{}, req)
	assert.Equal(t, float64(2), resp.ID)
	require.NotNil(t, resp.Result)

	var tools ToolListResult
	err := json.Unmarshal(*resp.Result, &tools)
	require.NoError(t, err)
	assert.Greater(t, len(tools.Tools), 0)

	toolNames := make(map[string]bool)
	for _, t := range tools.Tools {
		toolNames[t.Name] = true
	}
	assert.True(t, toolNames["findings_list"])
	assert.True(t, toolNames["findings_get"])
	assert.True(t, toolNames["gate_check"])
	assert.True(t, toolNames["waivers_list"])
	assert.True(t, toolNames["waivers_get"])
	assert.True(t, toolNames["waivers_create"])
	assert.True(t, toolNames["waivers_toggle"])
}

func TestMCPFindingsList(t *testing.T) {
	mc := &mockClient{
		findings: []client.Finding{
			{ID: "f1", CurrentTitle: "Test Vuln", CurrentSeverity: "high", GateEffect: "block"},
		},
	}
	params, _ := json.Marshal(map[string]any{"project": "my-app"})
	req := jsonRPCMessage{
		JSONRPC: "2.0",
		ID:      float64(3),
		Method:  "tools/call",
		Params:  &json.RawMessage{},
	}
	json.Unmarshal(params, req.Params)

	// Build a proper tools/call params
	raw := `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"findings_list","arguments":{"project":"my-app"}}}`
	var callReq jsonRPCMessage
	json.Unmarshal([]byte(raw), &callReq)

	resp := handleMessage(mc, callReq)
	assert.Equal(t, float64(3), resp.ID)
	require.Nil(t, resp.Error)
}

func TestMCPGateCheck(t *testing.T) {
	mc := &mockClient{
		gate: &client.GateStatus{ThresholdBreached: true, BlockingCount: 2},
	}
	raw := `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"gate_check","arguments":{"project":"my-app","severity":"critical"}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(mc, req)
	assert.Equal(t, float64(4), resp.ID)
	require.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)
	assert.True(t, strings.Contains(string(*resp.Result), "FAILED"))
}

func TestMCPGateCheckIntroducedOnly(t *testing.T) {
	mc := &mockClient{
		gate: &client.GateStatus{ThresholdBreached: false, BlockingCount: 0},
	}
	raw := `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"gate_check","arguments":{"project":"my-app","introduced_only":true,"report_id":"r1"}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(mc, req)
	require.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)
	assert.Equal(t, "r1", mc.introducedReport)
	assert.True(t, strings.Contains(string(*resp.Result), "PASSED"))
}

func TestMCPGateCheckIntroducedOnlyMissingReport(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"gate_check","arguments":{"project":"my-app","introduced_only":true}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(&mockClient{}, req)
	require.NotNil(t, resp.Error)
}

func TestMCPPrPreview(t *testing.T) {
	mc := &mockClient{
		preview: &client.PRCheckPreview{
			Conclusion: "failure", Title: "Specht: 1 blocking finding(s)",
			Annotations: []client.PRCheckAnnotation{{File: "app/main.go", StartLine: 10, Title: "XSS"}},
		},
	}
	raw := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"pr_preview","arguments":{"project":"my-app","commit":"abc123"}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(mc, req)
	require.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)
	assert.True(t, strings.Contains(string(*resp.Result), "failure"))
	assert.True(t, strings.Contains(string(*resp.Result), "app/main.go:10"))
}

func TestMCPPrPreviewMissingCommit(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"pr_preview","arguments":{"project":"my-app"}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(&mockClient{}, req)
	require.NotNil(t, resp.Error)
}

func TestMCPPatchPreview(t *testing.T) {
	mc := &mockClient{
		patch: &client.PatchOutcome{Reason: "secret findings are never auto-patched"},
	}
	raw := `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"patch_preview","arguments":{"finding_id":"f1"}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(mc, req)
	require.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)
	assert.True(t, strings.Contains(string(*resp.Result), "no patch"))
}

func TestMCPPatchPreviewMissingFinding(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":12,"method":"tools/call","params":{"name":"patch_preview","arguments":{}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(&mockClient{}, req)
	require.NotNil(t, resp.Error)
}

func TestMCPUnknownTool(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nonexistent","arguments":{}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(&mockClient{}, req)
	assert.Equal(t, float64(5), resp.ID)
	require.NotNil(t, resp.Error)
	assert.Equal(t, -32601, resp.Error.Code)
}

func TestMCPSendResponse(t *testing.T) {
	var buf strings.Builder
	resp := jsonRPCMessage{JSONRPC: "2.0", ID: float64(1)}
	sendResponse(&buf, resp)
	assert.True(t, strings.HasSuffix(buf.String(), "\n"))
	assert.True(t, strings.Contains(buf.String(), `"jsonrpc":"2.0"`))
}

func TestMCPReachabilitySet(t *testing.T) {
	mc := &mockClient{
		assessment: &client.ReachabilityAssessment{FindingID: "f1", State: "not_reachable", Evidence: "reviewed"},
	}
	raw := `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"reachability_set","arguments":{"finding_id":"f1","state":"not_reachable","evidence":"reviewed"}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(mc, req)
	assert.Equal(t, float64(6), resp.ID)
	require.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)
	assert.True(t, strings.Contains(string(*resp.Result), "state=not_reachable"))
}

func TestMCPReachabilitySet_MissingArgs(t *testing.T) {
	raw := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"reachability_set","arguments":{"finding_id":"f1"}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(&mockClient{}, req)
	assert.Equal(t, float64(7), resp.ID)
	require.NotNil(t, resp.Error)
	assert.Equal(t, -32602, resp.Error.Code)
}

func TestMCPGateCheck_ShowsReachability(t *testing.T) {
	mc := &mockClient{
		gate: &client.GateStatus{
			ThresholdBreached:     true,
			BlockingCount:         2,
			BlockedBy:             []string{"f1", "f2"},
			BlockedByReachability: map[string]string{"f1": "reachable", "f2": "not_reachable"},
		},
	}
	raw := `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"gate_check","arguments":{"project":"my-app"}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(mc, req)
	assert.Equal(t, float64(8), resp.ID)
	require.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)
	out := string(*resp.Result)
	assert.True(t, strings.Contains(out, "reachability: reachable"))
	assert.True(t, strings.Contains(out, "reachability: not_reachable"))
}

func TestMCPWatcherStatus(t *testing.T) {
	mc := &mockClient{watcher: &client.WatcherStatus{Healthy: true, ConsecutiveFailures: 0}}
	raw := `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"watcher_status","arguments":{}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(mc, req)
	assert.Equal(t, float64(9), resp.ID)
	require.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)
	assert.True(t, strings.Contains(string(*resp.Result), "healthy"))
}

func TestMCPWatcherStatus_Failing(t *testing.T) {
	mc := &mockClient{watcher: &client.WatcherStatus{Healthy: false, ConsecutiveFailures: 3, LastError: "osv timeout"}}
	raw := `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"watcher_status","arguments":{}}}`
	var req jsonRPCMessage
	json.Unmarshal([]byte(raw), &req)

	resp := handleMessage(mc, req)
	assert.Equal(t, float64(10), resp.ID)
	require.Nil(t, resp.Error)
	require.NotNil(t, resp.Result)
	out := string(*resp.Result)
	assert.True(t, strings.Contains(out, "FAILING"))
	assert.True(t, strings.Contains(out, "osv timeout"))
}
