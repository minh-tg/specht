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
