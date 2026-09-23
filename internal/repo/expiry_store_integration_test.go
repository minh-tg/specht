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

func TestExpiryStoresResetOnlyExpiredRecordsAndRecordAudits(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug:                "expiry-store",
		Name:                "Expiry store",
		DeploymentThreshold: "high",
		Settings:            json.RawMessage(`{}`),
	})
	require.NoError(t, err)

	now := time.Now().UTC()
	expiredFinding, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
		ProjectID:    project.ID,
		FindingKind:  "sca",
		Fingerprint:  "expiry-store-expired-finding",
		Title:        "Expiring analysis",
		Severity:     "high",
		SeverityRank: 3,
		FirstSeen:    now,
		LastSeen:     now,
	})
	require.NoError(t, err)
	futureFinding := createFindingForExpiry(t, ctx, stores, project.ID)

	expiredWaiver := createWaiverForExpiry(t, ctx, stores, project.ID, "expired waiver")
	futureWaiver := createWaiverForExpiry(t, ctx, stores, project.ID, "future waiver")
	permanentWaiver := createWaiverForExpiry(t, ctx, stores, project.ID, "permanent waiver")
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)
	_, err = repos.pool.Exec(ctx, "UPDATE waivers SET expires_at = $1 WHERE id = $2", past, mustParseID(expiredWaiver.ID))
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, "UPDATE waivers SET expires_at = $1 WHERE id = $2", future, mustParseID(futureWaiver.ID))
	require.NoError(t, err)

	_, err = stores.Findings.UpdateAnalysis(ctx, port.UpdateAnalysisInput{
		ID:                expiredFinding.ID,
		AnalysisState:     "accepted_risk",
		GateEffect:        "ignore",
		AnalysisExpiresAt: &past,
		AnalysisReason:    stringPointer("temporary"),
		AnalysisSource:    "manual",
		ManualOverride:    true,
		ReviewRequired:    true,
	})
	require.NoError(t, err)
	_, err = stores.Findings.UpdateAnalysis(ctx, port.UpdateAnalysisInput{
		ID:                futureFinding.ID,
		AnalysisState:     "accepted_risk",
		GateEffect:        "ignore",
		AnalysisExpiresAt: &future,
		AnalysisSource:    "manual",
		ManualOverride:    true,
		ReviewRequired:    true,
	})
	require.NoError(t, err)

	expiredWaivers, err := NewWaiverExpiryStore(repos.pool).ExpireExpired(ctx)
	require.NoError(t, err)
	require.Len(t, expiredWaivers, 1)
	require.Equal(t, expiredWaiver.ID, expiredWaivers[0].ID)
	require.False(t, expiredWaivers[0].Enabled)
	waiverEvents, err := stores.Waivers.ListEvents(ctx, expiredWaiver.ID)
	require.NoError(t, err)
	require.Len(t, waiverEvents, 2)
	require.ElementsMatch(t, []string{"created", "auto_disabled"}, []string{waiverEvents[0].EventType, waiverEvents[1].EventType})
	var autoDisabledEvent port.WaiverEvent
	for _, event := range waiverEvents {
		if event.EventType == "auto_disabled" {
			autoDisabledEvent = event
		}
	}
	require.JSONEq(t, `{"reason":"waiver_expired","waiver_name":"expired waiver"}`, string(autoDisabledEvent.Metadata))
	storedExpiredWaiver, err := stores.Waivers.GetByID(ctx, expiredWaiver.ID, project.ID)
	require.NoError(t, err)
	require.False(t, storedExpiredWaiver.Enabled)
	storedFutureWaiver, err := stores.Waivers.GetByID(ctx, futureWaiver.ID, project.ID)
	require.NoError(t, err)
	require.True(t, storedFutureWaiver.Enabled)
	storedPermanentWaiver, err := stores.Waivers.GetByID(ctx, permanentWaiver.ID, project.ID)
	require.NoError(t, err)
	require.True(t, storedPermanentWaiver.Enabled)
	expiredWaivers, err = NewWaiverExpiryStore(repos.pool).ExpireExpired(ctx)
	require.NoError(t, err)
	require.Empty(t, expiredWaivers)
	waiverEvents, err = stores.Waivers.ListEvents(ctx, expiredWaiver.ID)
	require.NoError(t, err)
	require.Len(t, waiverEvents, 2)

	expiredFindings, err := NewAnalysisExpiryStore(repos.pool).ExpireExpired(ctx)
	require.NoError(t, err)
	require.Len(t, expiredFindings, 1)
	require.Equal(t, expiredFinding.ID, expiredFindings[0].ID)
	require.Equal(t, "unanalyzed", expiredFindings[0].AnalysisState)
	require.Equal(t, "block", expiredFindings[0].GateEffect)
	storedExpiredFinding, err := stores.Findings.GetByID(ctx, expiredFinding.ID)
	require.NoError(t, err)
	require.Equal(t, "unanalyzed", storedExpiredFinding.AnalysisState)
	require.Equal(t, "block", storedExpiredFinding.GateEffect)
	require.Nil(t, storedExpiredFinding.AnalysisExpiresAt)
	findingEvents, err := stores.Findings.ListEvents(ctx, expiredFinding.ID, []string{"analysis_changed"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, findingEvents, 1)
	require.NotNil(t, findingEvents[0].Comment)
	require.Equal(t, "analysis expired, reset to unanalyzed", *findingEvents[0].Comment)
	require.JSONEq(t, `{"analysis_state":{"old":"accepted_risk","new":"unanalyzed"},"gate_effect":{"old":"ignore","new":"block"}}`, string(findingEvents[0].Changes))
	storedFutureFinding, err := stores.Findings.GetByID(ctx, futureFinding.ID)
	require.NoError(t, err)
	require.Equal(t, "accepted_risk", storedFutureFinding.AnalysisState)
	require.Equal(t, "ignore", storedFutureFinding.GateEffect)
	require.NotNil(t, storedFutureFinding.AnalysisExpiresAt)
	futureFindingByFingerprint, err := stores.Findings.GetByFingerprint(ctx, project.ID, "sca", "port-lifecycle-future-finding")
	require.NoError(t, err)
	require.Equal(t, futureFinding.ID, futureFindingByFingerprint.ID)
	expiredFindings, err = NewAnalysisExpiryStore(repos.pool).ExpireExpired(ctx)
	require.NoError(t, err)
	require.Empty(t, expiredFindings)
	findingEvents, err = stores.Findings.ListEvents(ctx, expiredFinding.ID, []string{"analysis_changed"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, findingEvents, 1)
}

func createWaiverForExpiry(t *testing.T, ctx context.Context, stores *port.Stores, projectID, name string) port.Waiver {
	t.Helper()
	waiver, err := stores.Waivers.CreateWithDetails(ctx, port.CreateWaiverInput{
		ProjectID: projectID,
		Name:      name,
		Enabled:   true,
		Event: port.WaiverEventInput{
			EventType: "created",
			Metadata:  json.RawMessage(`{}`),
		},
	})
	require.NoError(t, err)
	return waiver
}

func createFindingForExpiry(t *testing.T, ctx context.Context, stores *port.Stores, projectID string) port.Finding {
	t.Helper()
	now := time.Now().UTC()
	finding, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
		ProjectID:    projectID,
		FindingKind:  "sca",
		Fingerprint:  "port-lifecycle-future-finding",
		Title:        "Future analysis expiry",
		Severity:     "medium",
		SeverityRank: 2,
		Score:        5.4,
		FirstSeen:    now,
		LastSeen:     now,
	})
	require.NoError(t, err)
	return finding
}

func stringPointer(value string) *string {
	return &value
}
