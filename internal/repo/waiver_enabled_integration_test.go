//go:build integration

package repo

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func waiverEventTypes(t *testing.T, repos *Repos, waiver sqlc.Waiver) []string {
	t.Helper()
	events, err := repos.Waivers.ListEvents(context.Background(), waiver.ID)
	require.NoError(t, err)
	types := make([]string, 0, len(events))
	for _, e := range events {
		types = append(types, e.EventType)
	}
	return types
}

func revokeChange(actor string) port.WaiverEnabledChange {
	return port.WaiverEnabledChange{
		Enabled: false,
		Event:   port.WaiverEventInput{EventType: "revoked", ActorID: &actor, Metadata: json.RawMessage(`{}`)},
	}
}

func restoreChange(actor string) port.WaiverEnabledChange {
	return port.WaiverEnabledChange{
		Enabled: true,
		Event:   port.WaiverEventInput{EventType: "restored", ActorID: &actor, Metadata: json.RawMessage(`{}`)},
	}
}

func TestWaiverSetEnabledIsIdempotentAndRecordsActor(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	waiver, err := repos.Waivers.Create(ctx, sqlc.CreateWaiverParams{ProjectID: project.ID, Name: "idempotent", Enabled: true})
	require.NoError(t, err)
	stores := NewPortStores(repos.pool)
	id, pid := toUUID(waiver.ID), toUUID(project.ID)

	revoked, err := stores.Waivers.SetEnabled(ctx, id, pid, revokeChange("actor-1"))
	require.NoError(t, err)
	assert.False(t, revoked.Enabled)

	// A second revoke finds the wanted state and writes no event.
	again, err := stores.Waivers.SetEnabled(ctx, id, pid, revokeChange("actor-2"))
	require.NoError(t, err)
	assert.False(t, again.Enabled)
	assert.True(t, again.UpdatedAt.Equal(revoked.UpdatedAt), "a repeated revoke must not touch updated_at")
	assert.Equal(t, []string{"revoked"}, waiverEventTypes(t, repos, waiver))

	restored, err := stores.Waivers.SetEnabled(ctx, id, pid, restoreChange("actor-3"))
	require.NoError(t, err)
	assert.True(t, restored.Enabled)

	events, err := repos.Waivers.ListEvents(ctx, waiver.ID)
	require.NoError(t, err)
	require.Len(t, events, 2)
	byType := map[string]sqlc.WaiverEvent{}
	for _, e := range events {
		byType[e.EventType] = e
	}
	assert.Equal(t, "actor-1", byType["revoked"].ActorID.String)
	assert.Equal(t, "actor-3", byType["restored"].ActorID.String)
}

func TestWaiverSetEnabledExpectedUpdatedAtGuardsInterleavedWrites(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	waiver, err := repos.Waivers.Create(ctx, sqlc.CreateWaiverParams{ProjectID: project.ID, Name: "interleaved", Enabled: true})
	require.NoError(t, err)
	stores := NewPortStores(repos.pool)
	id, pid := toUUID(waiver.ID), toUUID(project.ID)

	// A revokes and keeps the version the response carried.
	aRevoked, err := stores.Waivers.SetEnabled(ctx, id, pid, revokeChange("a"))
	require.NoError(t, err)
	seenByA := aRevoked.UpdatedAt

	// B restores, then revokes again.
	_, err = stores.Waivers.SetEnabled(ctx, id, pid, restoreChange("b"))
	require.NoError(t, err)
	_, err = stores.Waivers.SetEnabled(ctx, id, pid, revokeChange("b"))
	require.NoError(t, err)

	// A's Undo carries the old version and must not override B.
	undo := restoreChange("a")
	undo.ExpectedUpdatedAt = &seenByA
	_, err = stores.Waivers.SetEnabled(ctx, id, pid, undo)
	require.ErrorIs(t, err, port.ErrWaiverChanged)

	// A stale precondition is a conflict even when the waiver already has the
	// wanted state: the caller is acting on a version that no longer exists.
	stale := revokeChange("a")
	stale.ExpectedUpdatedAt = &seenByA
	_, err = stores.Waivers.SetEnabled(ctx, id, pid, stale)
	require.ErrorIs(t, err, port.ErrWaiverChanged)

	current, err := repos.Waivers.GetByID(ctx, waiver.ID, project.ID)
	require.NoError(t, err)
	assert.False(t, current.Enabled, "the refused Undo must leave B's revoke in force")
	assert.Equal(t, []string{"revoked", "restored", "revoked"}, orderedEventTypes(t, repos, waiver))

	// A precondition that matches the current version succeeds.
	fresh := current.UpdatedAt.Time
	undo.ExpectedUpdatedAt = &fresh
	restored, err := stores.Waivers.SetEnabled(ctx, id, pid, undo)
	require.NoError(t, err)
	assert.True(t, restored.Enabled)
}

func orderedEventTypes(t *testing.T, repos *Repos, waiver sqlc.Waiver) []string {
	t.Helper()
	types := waiverEventTypes(t, repos, waiver)
	// ListWaiverEvents returns newest first.
	for i, j := 0, len(types)-1; i < j; i, j = i+1, j-1 {
		types[i], types[j] = types[j], types[i]
	}
	return types
}

func TestWaiverSetEnabledRefusesAnExpiredWaiver(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	waiver, err := repos.Waivers.Create(ctx, sqlc.CreateWaiverParams{ProjectID: project.ID, Name: "lapsed", Enabled: false})
	require.NoError(t, err)
	stores := NewPortStores(repos.pool)
	id, pid := toUUID(waiver.ID), toUUID(project.ID)

	past := time.Now().Add(-time.Hour)
	_, err = repos.pool.Exec(ctx, `UPDATE waivers SET expires_at = $2 WHERE id = $1`, waiver.ID, past)
	require.NoError(t, err)

	_, err = stores.Waivers.SetEnabled(ctx, id, pid, restoreChange("actor-1"))
	require.ErrorIs(t, err, port.ErrWaiverLapsed)
	_, err = stores.Waivers.ToggleWithEvent(ctx, id, pid, "actor-1")
	require.ErrorIs(t, err, port.ErrWaiverLapsed)
	assert.Empty(t, waiverEventTypes(t, repos, waiver), "a refused restore must not write an event")

	// Revoking an already disabled, expired waiver is a harmless repeat.
	still, err := stores.Waivers.SetEnabled(ctx, id, pid, revokeChange("actor-1"))
	require.NoError(t, err)
	assert.False(t, still.Enabled)

	// Extending the expiry makes the restore work again.
	future := time.Now().Add(time.Hour)
	_, err = repos.pool.Exec(ctx, `UPDATE waivers SET expires_at = $2 WHERE id = $1`, waiver.ID, future)
	require.NoError(t, err)
	restored, err := stores.Waivers.SetEnabled(ctx, id, pid, restoreChange("actor-1"))
	require.NoError(t, err)
	assert.True(t, restored.Enabled)
}

func TestWaiverSwitchesRefuseNonApprovedAndMissingWaivers(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	stores := NewPortStores(repos.pool)
	pid := toUUID(project.ID)

	for _, status := range []string{"pending", "rejected", "withdrawn"} {
		t.Run(status, func(t *testing.T) {
			waiver, err := repos.Waivers.Create(ctx, sqlc.CreateWaiverParams{
				ProjectID: project.ID, Name: status, Enabled: false, Status: status,
			})
			require.NoError(t, err)
			id := toUUID(waiver.ID)

			_, err = stores.Waivers.SetEnabled(ctx, id, pid, restoreChange("actor-1"))
			require.ErrorIs(t, err, port.ErrWaiverNotApproved)
			_, err = stores.Waivers.SetEnabled(ctx, id, pid, revokeChange("actor-1"))
			require.ErrorIs(t, err, port.ErrWaiverNotApproved)
			_, err = stores.Waivers.ToggleWithEvent(ctx, id, pid, "actor-1")
			require.ErrorIs(t, err, port.ErrWaiverNotApproved)

			current, err := repos.Waivers.GetByID(ctx, waiver.ID, project.ID)
			require.NoError(t, err)
			assert.False(t, current.Enabled)
			assert.Empty(t, waiverEventTypes(t, repos, waiver))
		})
	}

	missing := "00000000-0000-0000-0000-00000000dead"
	_, err := stores.Waivers.SetEnabled(ctx, missing, pid, revokeChange("actor-1"))
	require.ErrorIs(t, err, port.ErrNotFound)
	_, err = stores.Waivers.ToggleWithEvent(ctx, missing, pid, "actor-1")
	require.ErrorIs(t, err, port.ErrNotFound)
}

func TestWaiverSetEnabledEventFailureRollsBackTheChange(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	waiver, err := repos.Waivers.Create(ctx, sqlc.CreateWaiverParams{ProjectID: project.ID, Name: "atomic", Enabled: true})
	require.NoError(t, err)
	stores := NewPortStores(repos.pool)

	_, err = repos.pool.Exec(ctx, `
		ALTER TABLE waiver_events
		ADD CONSTRAINT test_reject_revoked_events CHECK (event_type <> 'revoked')
	`)
	require.NoError(t, err)

	_, err = stores.Waivers.SetEnabled(ctx, toUUID(waiver.ID), toUUID(project.ID), revokeChange("actor-1"))
	require.Error(t, err)

	unchanged, err := repos.Waivers.GetByID(ctx, waiver.ID, project.ID)
	require.NoError(t, err)
	assert.True(t, unchanged.Enabled, "a failed audit write must roll back the revoke")
}

func TestProjectWaiverCountIgnoresExpiredWaivers(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)

	_, err := repos.Waivers.Create(ctx, sqlc.CreateWaiverParams{ProjectID: project.ID, Name: "live", Enabled: true})
	require.NoError(t, err)
	stale, err := repos.Waivers.Create(ctx, sqlc.CreateWaiverParams{
		ProjectID: project.ID, Name: "stale", Enabled: true,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(time.Hour), Valid: true},
	})
	require.NoError(t, err)
	// The sweeper has not run yet, so the row is still enabled.
	_, err = repos.pool.Exec(ctx, `UPDATE waivers SET expires_at = NOW() - interval '1 minute' WHERE id = $1`, stale.ID)
	require.NoError(t, err)

	count, err := sqlc.New(repos.pool).GetProjectWaiverCount(ctx, project.ID)
	require.NoError(t, err)
	assert.Equal(t, int32(1), count, "an expired waiver that the sweeper has not disabled yet must not count")
}
