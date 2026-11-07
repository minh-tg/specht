package main

import (
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/client"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func gateCheckText(t *testing.T, api API, input gateCheckInput) string {
	t.Helper()
	res, _, err := handleGateCheck(api, input)
	if err != nil {
		t.Fatalf("handleGateCheck: %v", err)
	}
	if len(res.Content) != 1 {
		t.Fatalf("got %d content blocks, want 1", len(res.Content))
	}
	text, ok := res.Content[0].(*mcp.TextContent)
	if !ok {
		t.Fatalf("content is %T, want text", res.Content[0])
	}
	return text.Text
}

func TestGateCheckPassesTheBranchToTheVerdict(t *testing.T) {
	api := &mockClient{gate: &client.GateStatus{ThresholdBreached: true, BlockingCount: 2}}
	got := gateCheckText(t, api, gateCheckInput{Project: "p", Branch: "feature/x"})
	if api.gateBranch != "feature/x" {
		t.Fatalf("asked for branch %q, want feature/x", api.gateBranch)
	}
	if !strings.Contains(got, "gate FAILED on branch") || !strings.Contains(got, "feature/x") || !strings.Contains(got, "2 blocking") {
		t.Fatalf("verdict does not name the branch and count: %q", got)
	}
}

func TestGateCheckWithoutABranchAnswersForTheProject(t *testing.T) {
	api := &mockClient{gate: &client.GateStatus{}}
	got := gateCheckText(t, api, gateCheckInput{Project: "p"})
	if !api.gateCalled || api.gateBranch != "" {
		t.Fatalf("called=%v branch=%q, want the project verdict", api.gateCalled, api.gateBranch)
	}
	if got != "gate PASSED: no blocking findings" {
		t.Fatalf("got %q", got)
	}
}

func TestGateCheckNamesTheBranchInEveryVerdict(t *testing.T) {
	tests := map[string]struct {
		status client.GateStatus
		want   string
	}{
		"passed":      {client.GateStatus{}, "gate PASSED on branch"},
		"report only": {client.GateStatus{ThresholdBreached: true, ReportOnly: true, BlockingCount: 1}, "gate WOULD FAIL (report only) on branch"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got := gateCheckText(t, &mockClient{gate: &tc.status}, gateCheckInput{Project: "p", Branch: "dev"})
			if !strings.Contains(got, tc.want) {
				t.Fatalf("got %q, want it to contain %q", got, tc.want)
			}
		})
	}
}

func TestGateCheckRefusesBranchWithIntroducedOnly(t *testing.T) {
	api := &mockClient{gate: &client.GateStatus{}}
	_, _, err := handleGateCheck(api, gateCheckInput{Project: "p", Branch: "dev", IntroducedOnly: true, ReportID: "r"})
	if err == nil || !strings.Contains(err.Error(), "introduced_only") {
		t.Fatalf("got %v, want a refusal naming introduced_only", err)
	}
	if api.gateCalled || api.introducedReport != "" {
		t.Fatal("the refused call still reached the API")
	}
}
