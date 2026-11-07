package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/client"
)

func TestReportIntroducedGateCountsBlockersWithNoLine(t *testing.T) {
	preview := &client.PRCheckPreview{
		Annotations: []client.PRCheckAnnotation{
			{Level: "error", Title: "S3 bucket is public", File: "main.tf", StartLine: 1},
		},
		SummaryCounts: map[string]int{"high": 3},
	}
	var stderr bytes.Buffer

	code := reportIntroducedGate(&client.IngestResponse{ThresholdBreached: true}, preview, client.IngestPayload{}, &stderr)

	assert.Equal(t, 1, code)
	assert.Contains(t, stderr.String(), "NEW BLOCKING FINDINGS INTRODUCED IN THIS CHANGE (3):")
	assert.Contains(t, stderr.String(), "• S3 bucket is public: main.tf:1")
	assert.Contains(t, stderr.String(), "• and 2 more with no line to point at")
}

func TestReportIntroducedGateListsNothingExtraWhenEveryBlockerHasALine(t *testing.T) {
	preview := &client.PRCheckPreview{
		Annotations: []client.PRCheckAnnotation{
			{Level: "error", Title: "S3 bucket is public", File: "main.tf", StartLine: 1},
		},
		SummaryCounts: map[string]int{"high": 1},
	}
	var stderr bytes.Buffer

	reportIntroducedGate(&client.IngestResponse{ThresholdBreached: true}, preview, client.IngestPayload{}, &stderr)

	assert.Contains(t, stderr.String(), "NEW BLOCKING FINDINGS INTRODUCED IN THIS CHANGE (1):")
	assert.NotContains(t, stderr.String(), "more with no line")
}

// The ingest response counts every new finding, including those below the
// floor, so with only dependency blockers the summary is the number to print.
func TestReportIntroducedGateUsesTheSummaryWhenNoBlockerHasALine(t *testing.T) {
	preview := &client.PRCheckPreview{SummaryCounts: map[string]int{"critical": 1, "high": 1}}
	var stderr bytes.Buffer

	reportIntroducedGate(&client.IngestResponse{ThresholdBreached: true, IntroducedCount: 5}, preview, client.IngestPayload{}, &stderr)

	assert.Contains(t, stderr.String(), "NEW BLOCKING FINDINGS INTRODUCED IN THIS CHANGE: 2")
}

func TestReportIntroducedGateFallsBackToTheIngestCountWithoutAPreview(t *testing.T) {
	var stderr bytes.Buffer

	reportIntroducedGate(&client.IngestResponse{ThresholdBreached: true, IntroducedCount: 4}, nil, client.IngestPayload{}, &stderr)

	assert.Contains(t, stderr.String(), "NEW BLOCKING FINDINGS INTRODUCED IN THIS CHANGE: 4")
}
