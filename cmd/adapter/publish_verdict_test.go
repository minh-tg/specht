package main

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/client"
)

// Every scanner step publishes the same check, so the check carries the whole
// project's verdict even when the step's own scanner passes. Otherwise a clean
// Semgrep step finishing last would turn the commit green over Trivy blockers.
func TestApplyProjectVerdict_PublishesTheProjectVerdict(t *testing.T) {
	tests := map[string]struct {
		project, step  client.GateStatus
		wantConclusion string
		wantTitle      string
	}{
		"step passes, project blocks": {
			project:        client.GateStatus{ThresholdBreached: true, BlockingCount: 3},
			step:           client.GateStatus{},
			wantConclusion: "failure",
			wantTitle:      "Specht: 3 blocking finding(s)",
		},
		"step blocks, project report only": {
			project:        client.GateStatus{ThresholdBreached: true, ReportOnly: true, BlockingCount: 2},
			step:           client.GateStatus{ThresholdBreached: true, ReportOnly: true, BlockingCount: 2},
			wantConclusion: "neutral",
			wantTitle:      "Specht: 2 finding(s) would block (report only)",
		},
		"both pass": {
			project:        client.GateStatus{},
			step:           client.GateStatus{},
			wantConclusion: "success",
			wantTitle:      "Specht: gate passed",
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			preview := &client.PRCheckPreview{SummaryCounts: map[string]int{"high": 1}}
			applyProjectVerdict(preview, &tc.project, &tc.step, "semgrep")
			assert.Equal(t, tc.wantConclusion, preview.Conclusion)
			assert.Equal(t, tc.wantTitle, preview.Title)
			assert.Contains(t, preview.Summary, "of them from semgrep")
		})
	}
}
