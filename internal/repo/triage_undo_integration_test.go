//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// triageScenario seeds one project with one finding left unanalyzed.
type triageScenario struct {
	ctx       context.Context
	stores    *port.Stores
	projectID string
	findingID string
	userID    string
}

func newTriageScenario(t *testing.T) (*triageScenario, func()) {
	t.Helper()
	pool, cleanup := setupIngestPool(t)
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "triage", Name: "Triage", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	now := time.Now().UTC()
	f, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
		ProjectID: project.ID, FindingKind: "sca", Fingerprint: "fp-triage", Title: "CVE-2026-0001",
		Severity: "high", SeverityRank: 3, Score: 7.0, FirstSeen: now, LastSeen: now,
	})
	require.NoError(t, err)
	name, hash := "Triager", "hash"
	user, err := stores.Users.Create(ctx, "triager@example.test", &name, &hash)
	require.NoError(t, err)
	return &triageScenario{ctx: ctx, stores: stores, projectID: project.ID, findingID: f.ID, userID: user.ID}, cleanup
}

func (s *triageScenario) write(t *testing.T, state, expected string) (port.Finding, port.FindingEvent, error) {
	t.Helper()
	in := port.UpdateAnalysisInput{
		ID: s.findingID, AnalysisState: state, GateEffect: "block", AnalysisSource: "manual",
		ManualOverride: true, AnalysisUpdatedBy: &s.userID,
	}
	if expected != "" {
		in.ExpectedState = &expected
	}
	return s.stores.Findings.UpdateAnalysisWithEvent(s.ctx, in, port.FindingEventInput{
		FindingID: s.findingID, UserID: &s.userID, EventType: "analysis_changed",
	})
}

func TestUpdateAnalysisWithEvent_ExpectedStateGuard(t *testing.T) {
	s, cleanup := newTriageScenario(t)
	defer cleanup()

	t.Run("matching state writes and returns the event", func(t *testing.T) {
		got, ev, err := s.write(t, "in_triage", "unanalyzed")
		require.NoError(t, err)
		assert.Equal(t, "in_triage", got.AnalysisState)
		assert.NotEmpty(t, ev.ID)
	})

	t.Run("stale state is a conflict and writes nothing", func(t *testing.T) {
		_, _, err := s.write(t, "exploitable", "unanalyzed")
		require.ErrorIs(t, err, port.ErrAnalysisConflict)

		current, err := s.stores.Findings.GetByID(s.ctx, s.findingID)
		require.NoError(t, err)
		assert.Equal(t, "in_triage", current.AnalysisState)
		events, err := s.stores.Findings.ListEvents(s.ctx, s.findingID, []string{"analysis_changed"}, 10, 0)
		require.NoError(t, err)
		assert.Len(t, events, 1, "the refused write must not leave an event behind")
	})

	t.Run("no precondition writes unconditionally", func(t *testing.T) {
		got, _, err := s.write(t, "exploitable", "")
		require.NoError(t, err)
		assert.Equal(t, "exploitable", got.AnalysisState)
	})
}

func (s *triageScenario) event(t *testing.T, eventType string) port.FindingEvent {
	t.Helper()
	ev, err := s.stores.Findings.CreateEvent(s.ctx, port.FindingEventInput{
		FindingID: s.findingID, UserID: &s.userID, EventType: eventType,
	})
	require.NoError(t, err)
	return ev
}

func (s *triageScenario) eventCount(t *testing.T) int {
	t.Helper()
	events, err := s.stores.Findings.ListEvents(s.ctx, s.findingID, nil, 100, 0)
	require.NoError(t, err)
	return len(events)
}

// restore is a decider that puts the finding back to unanalyzed.
func (s *triageScenario) restore(port.Finding, *port.FindingEvent) (port.UpdateAnalysisInput, port.FindingEventInput, error) {
	return port.UpdateAnalysisInput{
			AnalysisState: "unanalyzed", GateEffect: "block", AnalysisSource: "manual", AnalysisUpdatedBy: &s.userID,
		}, port.FindingEventInput{
			UserID: &s.userID, EventType: "analysis_changed",
		}, nil
}

func TestUndoAnalysis_AppliesTheDecidedWriteAndEvent(t *testing.T) {
	s, cleanup := newTriageScenario(t)
	defer cleanup()
	_, triaged, err := s.write(t, "in_triage", "")
	require.NoError(t, err)

	reason := "restored reason"
	got, ev, err := s.stores.Findings.UndoAnalysis(s.ctx, s.findingID, func(cur port.Finding, newest *port.FindingEvent) (port.UpdateAnalysisInput, port.FindingEventInput, error) {
		require.NotNil(t, newest)
		assert.Equal(t, triaged.ID, newest.ID)
		assert.Equal(t, "in_triage", cur.AnalysisState)
		expiry := time.Now().Add(48 * time.Hour).UTC().Truncate(time.Microsecond)
		return port.UpdateAnalysisInput{
				AnalysisState: "accepted_risk", GateEffect: "ignore", AnalysisReason: &reason, AnalysisExpiresAt: &expiry,
				AnalysisSource: "auto_rule", ManualOverride: false, ReviewRequired: true, AnalysisUpdatedBy: &s.userID,
			}, port.FindingEventInput{
				UserID: &s.userID, EventType: "analysis_changed", OldValue: &cur.AnalysisState,
			}, nil
	})
	require.NoError(t, err)
	assert.NotEmpty(t, ev.ID)
	assert.NotEqual(t, triaged.ID, ev.ID, "the undo is a new event")
	assert.Equal(t, "accepted_risk", got.AnalysisState)

	stored, err := s.stores.Findings.GetByID(s.ctx, s.findingID)
	require.NoError(t, err)
	assert.Equal(t, "accepted_risk", stored.AnalysisState)
	assert.Equal(t, "ignore", stored.GateEffect)
	require.NotNil(t, stored.AnalysisReason)
	assert.Equal(t, reason, *stored.AnalysisReason)
	require.NotNil(t, stored.AnalysisExpiresAt)
	assert.Equal(t, "auto_rule", stored.AnalysisSource)
	assert.False(t, stored.ManualOverride)
	assert.True(t, stored.ReviewRequired)
	assert.Equal(t, 2, s.eventCount(t), "the original event stays in the history")
}

func TestUndoAnalysis_NewestEventIgnoresOtherEventTypes(t *testing.T) {
	s, cleanup := newTriageScenario(t)
	defer cleanup()

	seen := func() *port.FindingEvent {
		var got *port.FindingEvent
		_, _, err := s.stores.Findings.UndoAnalysis(s.ctx, s.findingID, func(_ port.Finding, newest *port.FindingEvent) (port.UpdateAnalysisInput, port.FindingEventInput, error) {
			got = newest
			return port.UpdateAnalysisInput{}, port.FindingEventInput{}, assert.AnError
		})
		require.ErrorIs(t, err, assert.AnError)
		return got
	}

	assert.Nil(t, seen(), "a finding with no analysis events has no newest event")

	_, triaged, err := s.write(t, "in_triage", "")
	require.NoError(t, err)
	s.event(t, "commented")
	got := seen()
	require.NotNil(t, got)
	assert.Equal(t, triaged.ID, got.ID, "a newer comment is not an analysis event")

	review := s.event(t, "reopened_severity_change")
	got = seen()
	require.NotNil(t, got)
	assert.Equal(t, review.ID, got.ID, "a scan review flag is newer than the triage")

	bulk := s.event(t, "bulk_triage_applied")
	got = seen()
	require.NotNil(t, got)
	assert.Equal(t, bulk.ID, got.ID)
}

func TestUndoAnalysis_DeciderErrorRollsBack(t *testing.T) {
	s, cleanup := newTriageScenario(t)
	defer cleanup()
	_, _, err := s.write(t, "in_triage", "")
	require.NoError(t, err)
	before := s.eventCount(t)

	_, _, err = s.stores.Findings.UndoAnalysis(s.ctx, s.findingID, func(port.Finding, *port.FindingEvent) (port.UpdateAnalysisInput, port.FindingEventInput, error) {
		return port.UpdateAnalysisInput{}, port.FindingEventInput{}, port.ErrAnalysisConflict
	})
	require.ErrorIs(t, err, port.ErrAnalysisConflict)

	stored, err := s.stores.Findings.GetByID(s.ctx, s.findingID)
	require.NoError(t, err)
	assert.Equal(t, "in_triage", stored.AnalysisState)
	assert.Equal(t, before, s.eventCount(t))
}

func TestUndoAnalysis_UnknownFinding(t *testing.T) {
	s, cleanup := newTriageScenario(t)
	defer cleanup()

	_, _, err := s.stores.Findings.UndoAnalysis(s.ctx, "00000000-0000-0000-0000-00000000dead", func(port.Finding, *port.FindingEvent) (port.UpdateAnalysisInput, port.FindingEventInput, error) {
		t.Fatal("decider must not run for a missing finding")
		return port.UpdateAnalysisInput{}, port.FindingEventInput{}, nil
	})
	require.ErrorIs(t, err, port.ErrNotFound)
}

// TestUndoAnalysis_HoldsTheRowLock proves the decision and the write are one
// atomic step: a triage that starts while the undo is deciding waits for it,
// then fails its expected_state check instead of overwriting the undo.
func TestUndoAnalysis_HoldsTheRowLock(t *testing.T) {
	s, cleanup := newTriageScenario(t)
	defer cleanup()
	_, _, err := s.write(t, "in_triage", "")
	require.NoError(t, err)

	entered := make(chan struct{})
	release := make(chan struct{})
	undoDone := make(chan error, 1)
	go func() {
		_, _, err := s.stores.Findings.UndoAnalysis(s.ctx, s.findingID, func(cur port.Finding, newest *port.FindingEvent) (port.UpdateAnalysisInput, port.FindingEventInput, error) {
			close(entered)
			<-release
			return s.restore(cur, newest)
		})
		undoDone <- err
	}()
	<-entered

	triageDone := make(chan error, 1)
	go func() {
		_, _, err := s.write(t, "exploitable", "in_triage")
		triageDone <- err
	}()

	select {
	case err := <-triageDone:
		close(release) // let the undo finish so cleanup does not wait on its connection
		<-undoDone
		t.Fatalf("a concurrent triage finished while the undo held the lock: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	close(release)
	require.NoError(t, <-undoDone)
	require.ErrorIs(t, <-triageDone, port.ErrAnalysisConflict)

	stored, err := s.stores.Findings.GetByID(s.ctx, s.findingID)
	require.NoError(t, err)
	assert.Equal(t, "unanalyzed", stored.AnalysisState, "the undo's write must survive the racing triage")
}
