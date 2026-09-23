//go:build integration

package repo

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/require"
)

func TestExpiryStoresRollbackWhenAuditWriteFails(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug:                "expiry-rollback",
		Name:                "Expiry rollback",
		DeploymentThreshold: "high",
		Settings:            json.RawMessage(`{}`),
	})
	require.NoError(t, err)

	cancelledCtx, cancel := context.WithCancel(ctx)
	cancel()
	_, err = NewAnalysisExpiryStore(repos.pool).ExpireExpired(cancelledCtx)
	require.ErrorIs(t, err, context.Canceled)
	_, err = NewWaiverExpiryStore(repos.pool).ExpireExpired(cancelledCtx)
	require.ErrorIs(t, err, context.Canceled)

	now := time.Now().UTC()
	finding, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
		ProjectID:    project.ID,
		FindingKind:  "sca",
		Fingerprint:  "expiry-rollback-finding",
		Title:        "Expiring analysis",
		Severity:     "high",
		SeverityRank: 3,
		FirstSeen:    now,
		LastSeen:     now,
	})
	require.NoError(t, err)
	past := now.Add(-time.Minute)
	_, err = stores.Findings.UpdateAnalysis(ctx, port.UpdateAnalysisInput{
		ID:                finding.ID,
		AnalysisState:     "accepted_risk",
		GateEffect:        "ignore",
		AnalysisExpiresAt: &past,
		AnalysisSource:    "manual",
		ManualOverride:    true,
	})
	require.NoError(t, err)

	waiver, err := stores.Waivers.CreateWithDetails(ctx, port.CreateWaiverInput{
		ProjectID: project.ID,
		Name:      "expiring waiver",
		Enabled:   true,
		Event: port.WaiverEventInput{
			EventType: "created",
			Metadata:  json.RawMessage(`{}`),
		},
	})
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, "UPDATE waivers SET expires_at = $1 WHERE id = $2", past, mustParseID(waiver.ID))
	require.NoError(t, err)

	_, err = repos.pool.Exec(ctx, `CREATE FUNCTION fail_expiry_audit_event() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'forced expiry audit failure';
END;
$$`)
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, `CREATE TRIGGER fail_finding_expiry_audit
BEFORE INSERT ON finding_events FOR EACH ROW
EXECUTE FUNCTION fail_expiry_audit_event()`)
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, `CREATE TRIGGER fail_waiver_expiry_audit
BEFORE INSERT ON waiver_events FOR EACH ROW
EXECUTE FUNCTION fail_expiry_audit_event()`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = repos.pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS fail_finding_expiry_audit ON finding_events")
		_, _ = repos.pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS fail_waiver_expiry_audit ON waiver_events")
		_, _ = repos.pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS fail_finding_expiry_commit ON finding_events")
		_, _ = repos.pool.Exec(context.Background(), "DROP TRIGGER IF EXISTS fail_waiver_expiry_commit ON waiver_events")
		_, _ = repos.pool.Exec(context.Background(), "DROP FUNCTION IF EXISTS fail_expiry_audit_event()")
	})

	_, err = NewAnalysisExpiryStore(repos.pool).ExpireExpired(ctx)
	require.ErrorContains(t, err, "create event")
	require.ErrorContains(t, err, "forced expiry audit failure")
	storedFinding, err := stores.Findings.GetByID(ctx, finding.ID)
	require.NoError(t, err)
	require.Equal(t, "accepted_risk", storedFinding.AnalysisState)
	require.Equal(t, "ignore", storedFinding.GateEffect)
	require.NotNil(t, storedFinding.AnalysisExpiresAt)
	findingEvents, err := stores.Findings.ListEvents(ctx, finding.ID, []string{"analysis_changed"}, 10, 0)
	require.NoError(t, err)
	require.Empty(t, findingEvents)

	_, err = NewWaiverExpiryStore(repos.pool).ExpireExpired(ctx)
	require.ErrorContains(t, err, "create waiver event")
	require.ErrorContains(t, err, "forced expiry audit failure")
	storedWaiver, err := stores.Waivers.GetByID(ctx, waiver.ID, project.ID)
	require.NoError(t, err)
	require.True(t, storedWaiver.Enabled)
	waiverEvents, err := stores.Waivers.ListEvents(ctx, waiver.ID)
	require.NoError(t, err)
	require.Len(t, waiverEvents, 1)
	require.Equal(t, "created", waiverEvents[0].EventType)

	_, err = repos.pool.Exec(ctx, "DROP TRIGGER fail_finding_expiry_audit ON finding_events")
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, "DROP TRIGGER fail_waiver_expiry_audit ON waiver_events")
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, `CREATE CONSTRAINT TRIGGER fail_finding_expiry_commit
AFTER INSERT ON finding_events DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW WHEN (NEW.event_type = 'analysis_changed')
EXECUTE FUNCTION fail_expiry_audit_event()`)
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, `CREATE CONSTRAINT TRIGGER fail_waiver_expiry_commit
AFTER INSERT ON waiver_events DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW WHEN (NEW.event_type = 'auto_disabled')
EXECUTE FUNCTION fail_expiry_audit_event()`)
	require.NoError(t, err)

	_, err = NewAnalysisExpiryStore(repos.pool).ExpireExpired(ctx)
	require.ErrorContains(t, err, "commit tx")
	require.ErrorContains(t, err, "forced expiry audit failure")
	storedFinding, err = stores.Findings.GetByID(ctx, finding.ID)
	require.NoError(t, err)
	require.Equal(t, "accepted_risk", storedFinding.AnalysisState)
	require.Equal(t, "ignore", storedFinding.GateEffect)
	require.NotNil(t, storedFinding.AnalysisExpiresAt)
	findingEvents, err = stores.Findings.ListEvents(ctx, finding.ID, []string{"analysis_changed"}, 10, 0)
	require.NoError(t, err)
	require.Empty(t, findingEvents)

	_, err = NewWaiverExpiryStore(repos.pool).ExpireExpired(ctx)
	require.ErrorContains(t, err, "commit tx")
	require.ErrorContains(t, err, "forced expiry audit failure")
	storedWaiver, err = stores.Waivers.GetByID(ctx, waiver.ID, project.ID)
	require.NoError(t, err)
	require.True(t, storedWaiver.Enabled)
	waiverEvents, err = stores.Waivers.ListEvents(ctx, waiver.ID)
	require.NoError(t, err)
	require.Len(t, waiverEvents, 1)
	require.Equal(t, "created", waiverEvents[0].EventType)
}
