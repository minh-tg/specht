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

const (
	snapshotFindingID = "00000000-0000-0000-0000-000000000021"
	snapshotUserID    = "00000000-0000-0000-0000-000000000040"
)

// triageFixture wires a finding in a chosen analysis state and captures what
// the triage write sends to the store.
type triageFixture struct {
	uc      *Usecases
	update  *port.UpdateAnalysisInput
	event   *port.FindingEventInput
	current port.Finding
}

func newTriageFixture(t *testing.T, current port.Finding) *triageFixture {
	t.Helper()
	fx := &triageFixture{current: current}
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(context.Context, string) (port.Finding, error) { return current, nil }
	fr.updateAnalysisWithEventFn = func(_ context.Context, in port.UpdateAnalysisInput, ev port.FindingEventInput) (port.Finding, port.FindingEvent, error) {
		fx.update, fx.event = &in, &ev
		updated := current
		updated.AnalysisState = in.AnalysisState
		updated.GateEffect = in.GateEffect
		return updated, port.FindingEvent{ID: "00000000-0000-0000-0000-0000000000e1"}, nil
	}
	fx.uc = New(Deps{Stores: &port.Stores{Findings: fr, Projects: memberProjects()}})
	return fx
}

func (fx *triageFixture) triage(t *testing.T, in TriageInput) (*TriageOutput, error) {
	t.Helper()
	in.FindingID = snapshotFindingID
	in.UserID = snapshotUserID
	return fx.uc.TriageFinding(findingScopeCtx(findingFixtureProjectID), in)
}

func TestTriageFinding_RecordsBeforeSnapshot(t *testing.T) {
	expiry := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	reason := "vendor patch pending"
	current := makeFindingRow(1)
	current.AnalysisState = "accepted_risk"
	current.GateEffect = "ignore"
	current.AnalysisReason = &reason
	current.AnalysisExpiresAt = &expiry
	current.AnalysisSource = "auto_rule"
	current.ManualOverride = false
	current.ReviewRequired = true
	fx := newTriageFixture(t, current)

	out, err := fx.triage(t, TriageInput{AnalysisState: "exploitable"})
	require.NoError(t, err)
	assert.Equal(t, "00000000-0000-0000-0000-0000000000e1", out.EventID)

	require.NotNil(t, fx.event)
	assert.Equal(t, "analysis_changed", fx.event.EventType)
	var changes struct {
		From   string           `json:"from"`
		To     string           `json:"to"`
		Before analysisSnapshot `json:"before"`
	}
	require.NoError(t, json.Unmarshal(fx.event.Changes, &changes))
	assert.Equal(t, "accepted_risk", changes.From)
	assert.Equal(t, "exploitable", changes.To)
	assert.Equal(t, "accepted_risk", changes.Before.AnalysisState)
	require.NotNil(t, changes.Before.AnalysisReason)
	assert.Equal(t, reason, *changes.Before.AnalysisReason)
	require.NotNil(t, changes.Before.AnalysisExpiresAt)
	assert.True(t, expiry.Equal(*changes.Before.AnalysisExpiresAt))
	assert.Equal(t, "auto_rule", changes.Before.AnalysisSource)
	assert.False(t, changes.Before.ManualOverride)
	assert.True(t, changes.Before.ReviewRequired)
}

func TestTriageFinding_SnapshotKeepsNullReasonAndExpiry(t *testing.T) {
	fx := newTriageFixture(t, makeFindingRow(1))

	_, err := fx.triage(t, TriageInput{AnalysisState: "in_triage"})
	require.NoError(t, err)

	var raw struct {
		Before map[string]json.RawMessage `json:"before"`
	}
	require.NoError(t, json.Unmarshal(fx.event.Changes, &raw))
	assert.JSONEq(t, `null`, string(raw.Before["analysis_reason"]))
	assert.JSONEq(t, `null`, string(raw.Before["analysis_expires_at"]))
}

func TestTriageFinding_GuardsWriteWithReadState(t *testing.T) {
	current := makeFindingRow(1)
	current.AnalysisState = "in_triage"
	fx := newTriageFixture(t, current)

	_, err := fx.triage(t, TriageInput{AnalysisState: "exploitable"})
	require.NoError(t, err)

	require.NotNil(t, fx.update.ExpectedState)
	assert.Equal(t, "in_triage", *fx.update.ExpectedState)
}

func TestTriageFinding_ExpectedStateMismatchIsConflict(t *testing.T) {
	current := makeFindingRow(1)
	current.AnalysisState = "in_triage"
	fx := newTriageFixture(t, current)

	_, err := fx.triage(t, TriageInput{AnalysisState: "exploitable", ExpectedState: "unanalyzed"})
	require.ErrorIs(t, err, ErrAnalysisConflict)
	assert.Nil(t, fx.update, "a stale expected_state must not reach the store")
}

func TestTriageFinding_ExpectedStateMatchWrites(t *testing.T) {
	current := makeFindingRow(1)
	current.AnalysisState = "in_triage"
	fx := newTriageFixture(t, current)

	_, err := fx.triage(t, TriageInput{AnalysisState: "exploitable", ExpectedState: "in_triage"})
	require.NoError(t, err)
	require.NotNil(t, fx.update)
}

func TestTriageFinding_StoreConflictSurfaces(t *testing.T) {
	fx := newTriageFixture(t, makeFindingRow(1))
	fr := fx.uc.deps.Stores.Findings.(*mockFindingRepo)
	fr.updateAnalysisWithEventFn = func(context.Context, port.UpdateAnalysisInput, port.FindingEventInput) (port.Finding, port.FindingEvent, error) {
		return port.Finding{}, port.FindingEvent{}, port.ErrAnalysisConflict
	}

	_, err := fx.triage(t, TriageInput{AnalysisState: "exploitable"})
	require.ErrorIs(t, err, ErrAnalysisConflict)
}
