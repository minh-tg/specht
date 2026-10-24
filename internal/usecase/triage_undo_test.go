package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const undoEventID = "00000000-0000-0000-0000-0000000000e1"

// undoFixture is an in-memory finding with an event log. Its UndoAnalysis
// runs the decider against the current row and the newest analysis event the
// way the locking store does, and applies the result.
type undoFixture struct {
	uc      *Usecases
	current port.Finding
	newest  *port.FindingEvent
	applied *port.UpdateAnalysisInput
	logged  *port.FindingEventInput
}

func newUndoFixture(t *testing.T, current port.Finding, newest *port.FindingEvent) *undoFixture {
	t.Helper()
	fx := &undoFixture{current: current, newest: newest}
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(context.Context, string) (port.Finding, error) { return fx.current, nil }
	fr.undoAnalysisFn = func(_ context.Context, _ string, decide port.AnalysisUndoDecider) (port.Finding, port.FindingEvent, error) {
		in, ev, err := decide(fx.current, fx.newest)
		if err != nil {
			return port.Finding{}, port.FindingEvent{}, err
		}
		fx.applied, fx.logged = &in, &ev
		updated := fx.current
		updated.AnalysisState, updated.GateEffect = in.AnalysisState, in.GateEffect
		return updated, port.FindingEvent{ID: "00000000-0000-0000-0000-0000000000e2"}, nil
	}
	fx.uc = New(Deps{Stores: &port.Stores{Findings: fr, Projects: memberProjects()}})
	return fx
}

func (fx *undoFixture) undo(eventID string) (*TriageOutput, error) {
	return fx.uc.UndoTriage(findingScopeCtx(findingFixtureProjectID), UndoTriageInput{
		FindingID: snapshotFindingID, EventID: eventID, UserID: snapshotUserID,
	})
}

// triageEvent builds the analysis_changed event a triage write leaves.
func triageEvent(t *testing.T, id, from, to string, before *analysisSnapshot) *port.FindingEvent {
	t.Helper()
	body := map[string]any{"from": from, "to": to, "reason": "r"}
	if before != nil {
		body["before"] = before
	}
	changes, err := json.Marshal(body)
	require.NoError(t, err)
	return &port.FindingEvent{ID: id, EventType: "analysis_changed", Changes: changes}
}

func findingIn(state string) port.Finding {
	f := makeFindingRow(1)
	f.AnalysisState = state
	return f
}

func TestUndoTriage_RestoresEveryPreviousState(t *testing.T) {
	future := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	reason := "documented in RISK-12"
	cases := []struct {
		name       string
		before     analysisSnapshot
		wantEffect string
	}{
		{"unanalyzed", analysisSnapshot{AnalysisState: "unanalyzed", AnalysisSource: "manual"}, "block"},
		{"in_triage", analysisSnapshot{AnalysisState: "in_triage", AnalysisSource: "manual", ManualOverride: true}, "block"},
		{"exploitable", analysisSnapshot{AnalysisState: "exploitable", AnalysisSource: "manual", ManualOverride: true}, "block"},
		{"false_positive", analysisSnapshot{AnalysisState: "false_positive", AnalysisReason: &reason, AnalysisSource: "auto_rule", ManualOverride: false}, "ignore"},
		{"not_affected", analysisSnapshot{AnalysisState: "not_affected", AnalysisReason: &reason, AnalysisSource: "auto_rule"}, "ignore"},
		{"accepted_risk", analysisSnapshot{AnalysisState: "accepted_risk", AnalysisReason: &reason, AnalysisExpiresAt: &future, AnalysisSource: "manual", ManualOverride: true, ReviewRequired: true}, "ignore"},
		{"wont_fix", analysisSnapshot{AnalysisState: "wont_fix", AnalysisReason: &reason, AnalysisExpiresAt: &future, AnalysisSource: "manual", ManualOverride: true}, "ignore"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := tc.before
			fx := newUndoFixture(t, findingIn("in_triage"), triageEvent(t, undoEventID, tc.name, "in_triage", &before))

			out, err := fx.undo(undoEventID)
			require.NoError(t, err)
			assert.Equal(t, tc.name, out.AnalysisState)
			assert.Equal(t, tc.wantEffect, out.GateEffect)
			assert.Equal(t, "00000000-0000-0000-0000-0000000000e2", out.EventID)

			in := fx.applied
			require.NotNil(t, in)
			assert.Equal(t, tc.name, in.AnalysisState)
			assert.Equal(t, tc.wantEffect, in.GateEffect)
			assert.Equal(t, before.AnalysisReason, in.AnalysisReason)
			assert.Equal(t, before.AnalysisExpiresAt, in.AnalysisExpiresAt)
			assert.Equal(t, before.AnalysisSource, in.AnalysisSource)
			assert.Equal(t, before.ManualOverride, in.ManualOverride)
			assert.Equal(t, before.ReviewRequired, in.ReviewRequired)
			require.NotNil(t, in.AnalysisUpdatedBy)
			assert.Equal(t, snapshotUserID, *in.AnalysisUpdatedBy)
		})
	}
}

func TestUndoTriage_WritesANewAttributedEvent(t *testing.T) {
	before := analysisSnapshot{AnalysisState: "unanalyzed", AnalysisSource: "manual"}
	fx := newUndoFixture(t, findingIn("in_triage"), triageEvent(t, undoEventID, "unanalyzed", "in_triage", &before))

	_, err := fx.undo(undoEventID)
	require.NoError(t, err)

	ev := fx.logged
	require.NotNil(t, ev)
	assert.Equal(t, "analysis_changed", ev.EventType)
	require.NotNil(t, ev.UserID)
	assert.Equal(t, snapshotUserID, *ev.UserID)
	assert.Equal(t, "in_triage", derefStr(ev.OldValue))
	assert.Equal(t, "unanalyzed", derefStr(ev.NewValue))
	var changes struct {
		From   string           `json:"from"`
		To     string           `json:"to"`
		UndoOf string           `json:"undo_of"`
		Before analysisSnapshot `json:"before"`
	}
	require.NoError(t, json.Unmarshal(ev.Changes, &changes))
	assert.Equal(t, "in_triage", changes.From)
	assert.Equal(t, "unanalyzed", changes.To)
	assert.Equal(t, undoEventID, changes.UndoOf)
	assert.Equal(t, "in_triage", changes.Before.AnalysisState, "the undo event keeps a snapshot so it can be undone in turn")
}

func TestUndoTriage_UndoEventCanItselfBeUndone(t *testing.T) {
	before := analysisSnapshot{AnalysisState: "unanalyzed", AnalysisSource: "manual"}
	fx := newUndoFixture(t, findingIn("in_triage"), triageEvent(t, undoEventID, "unanalyzed", "in_triage", &before))
	_, err := fx.undo(undoEventID)
	require.NoError(t, err)

	redo := &port.FindingEvent{ID: "00000000-0000-0000-0000-0000000000e2", EventType: "analysis_changed", Changes: fx.logged.Changes}
	again := newUndoFixture(t, findingIn("unanalyzed"), redo)
	out, err := again.undo(redo.ID)
	require.NoError(t, err)
	assert.Equal(t, "in_triage", out.AnalysisState)
}

func TestUndoTriage_Conflicts(t *testing.T) {
	before := analysisSnapshot{AnalysisState: "unanalyzed", AnalysisSource: "manual"}
	const otherID = "00000000-0000-0000-0000-0000000000e9"
	cases := []struct {
		name    string
		current port.Finding
		newest  *port.FindingEvent
	}{
		{"a newer analysis event exists", findingIn("exploitable"), triageEvent(t, otherID, "in_triage", "exploitable", &before)},
		{"a newer scan review event exists", findingIn("in_triage"), &port.FindingEvent{ID: otherID, EventType: "reopened_severity_change", Changes: json.RawMessage(`{}`)}},
		{"the finding has no analysis events", findingIn("in_triage"), nil},
		{"the state moved since the event", findingIn("exploitable"), triageEvent(t, undoEventID, "unanalyzed", "in_triage", &before)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newUndoFixture(t, tc.current, tc.newest)
			_, err := fx.undo(undoEventID)
			require.ErrorIs(t, err, ErrAnalysisConflict)
			assert.Nil(t, fx.applied, "a refused undo must not write")
		})
	}
}

func TestUndoTriage_UnavailableWithoutSnapshot(t *testing.T) {
	cases := []struct {
		name   string
		newest *port.FindingEvent
	}{
		{"event written before snapshots existed", triageEvent(t, undoEventID, "unanalyzed", "in_triage", nil)},
		{"bulk triage event", &port.FindingEvent{ID: undoEventID, EventType: "bulk_triage_applied", Changes: json.RawMessage(`{"to":"in_triage","count":3}`)}},
		{"bulk triage event even with a snapshot", &port.FindingEvent{ID: undoEventID, EventType: "bulk_triage_applied", Changes: json.RawMessage(`{"to":"in_triage","before":{"analysis_state":"unanalyzed","analysis_source":"manual"}}`)}},
		{"scan review event", &port.FindingEvent{ID: undoEventID, EventType: "reopened_fix_available", Changes: json.RawMessage(`{"event":"fix_available"}`)}},
		{"expiry sweep event", &port.FindingEvent{ID: undoEventID, EventType: "analysis_changed", Changes: json.RawMessage(`{"analysis_state":{"old":"accepted_risk","new":"unanalyzed"}}`)}},
		{"unreadable changes", &port.FindingEvent{ID: undoEventID, EventType: "analysis_changed", Changes: json.RawMessage(`not json`)}},
		{"snapshot with an unknown state", triageEvent(t, undoEventID, "x", "in_triage", &analysisSnapshot{AnalysisState: "bogus"})},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := newUndoFixture(t, findingIn("in_triage"), tc.newest)
			_, err := fx.undo(undoEventID)
			require.ErrorIs(t, err, ErrUndoUnavailable)
			assert.Nil(t, fx.applied)
		})
	}
}

func TestUndoTriage_PreviousExpiryPassed(t *testing.T) {
	reason := "r"
	for name, expiry := range map[string]time.Time{
		"an hour ago":   time.Now().Add(-time.Hour),
		"just now":      time.Now().Add(-time.Millisecond),
		"a year ago":    time.Now().AddDate(-1, 0, 0),
		"the epoch day": time.Unix(0, 0),
	} {
		t.Run(name, func(t *testing.T) {
			before := analysisSnapshot{AnalysisState: "accepted_risk", AnalysisReason: &reason, AnalysisExpiresAt: &expiry, AnalysisSource: "manual"}
			fx := newUndoFixture(t, findingIn("in_triage"), triageEvent(t, undoEventID, "accepted_risk", "in_triage", &before))
			_, err := fx.undo(undoEventID)
			require.ErrorIs(t, err, ErrPreviousExpiryPassed)
			assert.Nil(t, fx.applied)
		})
	}
}

func TestUndoTriage_RequiresProjectEditor(t *testing.T) {
	before := analysisSnapshot{AnalysisState: "unanalyzed", AnalysisSource: "manual"}
	fx := newUndoFixture(t, findingIn("in_triage"), triageEvent(t, undoEventID, "unanalyzed", "in_triage", &before))
	ctx := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID:    snapshotUserID,
		ProjectID: "00000000-0000-0000-0000-000000000002",
		IsAPIKey:  true,
	})

	_, err := fx.uc.UndoTriage(ctx, UndoTriageInput{FindingID: snapshotFindingID, EventID: undoEventID, UserID: snapshotUserID})
	require.ErrorIs(t, err, ErrFindingNotFound)
	assert.Nil(t, fx.applied)
}

func TestUndoTriage_InputErrors(t *testing.T) {
	fx := newUndoFixture(t, findingIn("in_triage"), nil)
	ctx := findingScopeCtx(findingFixtureProjectID)

	_, err := fx.uc.UndoTriage(ctx, UndoTriageInput{FindingID: "nope", EventID: undoEventID, UserID: snapshotUserID})
	require.ErrorIs(t, err, ErrInvalidFindingID)
	_, err = fx.uc.UndoTriage(ctx, UndoTriageInput{FindingID: snapshotFindingID, EventID: "nope", UserID: snapshotUserID})
	require.ErrorIs(t, err, ErrInvalidEventID)
	_, err = fx.uc.UndoTriage(ctx, UndoTriageInput{FindingID: snapshotFindingID, EventID: undoEventID, UserID: "nope"})
	require.Error(t, err)
}

func TestUndoTriage_FindingMissing(t *testing.T) {
	fr := &mockFindingRepo{}
	fr.getByIDFn = func(context.Context, string) (port.Finding, error) { return port.Finding{}, port.ErrNotFound }
	uc := New(Deps{Stores: &port.Stores{Findings: fr, Projects: memberProjects()}})

	_, err := uc.UndoTriage(findingScopeCtx(findingFixtureProjectID), UndoTriageInput{
		FindingID: snapshotFindingID, EventID: undoEventID, UserID: snapshotUserID,
	})
	require.ErrorIs(t, err, ErrFindingNotFound)
}

func TestUndoTriage_StoreErrorsSurface(t *testing.T) {
	fx := newUndoFixture(t, findingIn("in_triage"), nil)
	fr := fx.uc.deps.Stores.Findings.(*mockFindingRepo)

	fr.undoAnalysisFn = func(context.Context, string, port.AnalysisUndoDecider) (port.Finding, port.FindingEvent, error) {
		return port.Finding{}, port.FindingEvent{}, port.ErrNotFound
	}
	_, err := fx.undo(undoEventID)
	require.ErrorIs(t, err, ErrFindingNotFound, "the finding deleted between the check and the lock")

	boom := errors.New("connection reset")
	fr.undoAnalysisFn = func(context.Context, string, port.AnalysisUndoDecider) (port.Finding, port.FindingEvent, error) {
		return port.Finding{}, port.FindingEvent{}, boom
	}
	_, err = fx.undo(undoEventID)
	require.ErrorIs(t, err, boom)
}
