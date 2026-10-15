package usecase

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestGetFinding_CarriesTheAnalysisDecisionFields(t *testing.T) {
	reason := "covered by the WAF rule"
	expiry := time.Date(2031, 3, 4, 5, 6, 7, 0, time.UTC)
	row := makeFindingRow(1)
	row.AnalysisState = "accepted_risk"
	row.AnalysisReason = &reason
	row.AnalysisExpiresAt = &expiry
	row.AnalysisSource = "manual"
	row.ManualOverride = true
	row.ReviewRequired = true
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(context.Context, string) (port.Finding, error) { return row, nil }

	uc := New(Deps{Stores: memberFindingDeps(fr)})
	got, err := uc.GetFinding(memberSessionCtx(), "00000000-0000-0000-0000-000000000021")
	require.NoError(t, err)

	require.NotNil(t, got.AnalysisReason)
	assert.Equal(t, reason, *got.AnalysisReason)
	require.NotNil(t, got.AnalysisExpiresAt)
	assert.True(t, expiry.Equal(*got.AnalysisExpiresAt))
	assert.Equal(t, "manual", got.AnalysisSource)
	assert.True(t, got.ManualOverride)
	assert.True(t, got.ReviewRequired)
}

func TestFindingResponse_OmitsAnAbsentReasonAndExpiry(t *testing.T) {
	row := makeFindingRow(1)
	row.AnalysisSource = "system"

	raw, err := json.Marshal(toFinding(row))
	require.NoError(t, err)
	var body map[string]any
	require.NoError(t, json.Unmarshal(raw, &body))

	assert.NotContains(t, body, "analysis_reason")
	assert.NotContains(t, body, "analysis_expires_at")
	assert.Equal(t, "system", body["analysis_source"])
	assert.Equal(t, false, body["manual_override"])
	assert.Equal(t, false, body["review_required"])
}
