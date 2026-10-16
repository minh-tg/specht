//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// A deleted waiver leaves its identity, scope and events in waiver_deletions,
// with the deleter, and the record refuses updates.
func TestWaiverDeleteKeepsAnAppendOnlyRecord(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	projectID := toUUID(project.ID)
	stores := NewPortStores(repos.pool)

	waiver, err := stores.Waivers.CreateWithDetails(ctx, port.CreateWaiverInput{
		ProjectID:  projectID,
		Name:       "release window",
		Enabled:    true,
		Status:     "approved",
		Conditions: []port.WaiverCondition{{Field: "severity_rank", Operator: "lte", Value: "3"}},
		Event:      port.WaiverEventInput{EventType: "created", Metadata: []byte(`{}`)},
	})
	require.NoError(t, err)
	actor := "00000000-0000-0000-0000-0000000000a1"
	_, err = stores.Waivers.SetEnabled(ctx, waiver.ID, projectID, port.WaiverEnabledChange{
		Enabled: false,
		Event:   port.WaiverEventInput{EventType: "revoked", ActorID: &actor, Metadata: []byte(`{}`)},
	})
	require.NoError(t, err)

	require.NoError(t, stores.Waivers.Delete(ctx, waiver.ID, projectID, actor))

	_, err = stores.Waivers.GetByID(ctx, waiver.ID, projectID)
	require.ErrorIs(t, err, port.ErrNotFound)
	var live int
	require.NoError(t, repos.pool.QueryRow(ctx,
		`SELECT count(*) FROM waiver_events WHERE waiver_id = $1`, waiver.ID).Scan(&live))
	require.Zero(t, live, "the live event rows cascade away with the waiver")

	var (
		deletedBy string
		name      string
		conds     int
		events    int
		types     []string
	)
	require.NoError(t, repos.pool.QueryRow(ctx, `
		SELECT deleted_by, snapshot->'waiver'->>'name',
		       jsonb_array_length(snapshot->'conditions'), jsonb_array_length(snapshot->'events'),
		       ARRAY(SELECT e->>'event_type' FROM jsonb_array_elements(snapshot->'events') e ORDER BY e->>'created_at', e->>'event_type')
		  FROM waiver_deletions WHERE waiver_id = $1`, waiver.ID).
		Scan(&deletedBy, &name, &conds, &events, &types))
	assert.Equal(t, actor, deletedBy)
	assert.Equal(t, "release window", name)
	assert.Equal(t, 1, conds)
	assert.Equal(t, 2, events)
	assert.ElementsMatch(t, []string{"created", "revoked"}, types)

	_, err = repos.pool.Exec(ctx, `UPDATE waiver_deletions SET deleted_by = 'someone else' WHERE waiver_id = $1`, waiver.ID)
	require.Error(t, err, "the record is append-only")
}

// A delete that finds no waiver writes no record.
func TestWaiverDeleteOfMissingWaiverWritesNoRecord(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	stores := NewPortStores(repos.pool)

	err := stores.Waivers.Delete(ctx, "00000000-0000-0000-0000-0000000000b2", toUUID(project.ID), "")
	require.ErrorIs(t, err, port.ErrNotFound)

	var n int
	require.NoError(t, repos.pool.QueryRow(ctx, `SELECT count(*) FROM waiver_deletions`).Scan(&n))
	require.Zero(t, n)
}

// A context column left NULL reads back as "", never as the all-zero UUID, so
// the gate sees it as a wildcard and not as an environment that matches nothing.
func TestWaiverContextReadsNullColumnsAsEmpty(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)
	projectID := toUUID(project.ID)
	stores := NewPortStores(repos.pool)

	target, err := stores.Targets.Upsert(ctx, projectID, "app", "repo", "https://github.com/example/app", "")
	require.NoError(t, err)
	waiver, err := stores.Waivers.CreateWithDetails(ctx, port.CreateWaiverInput{
		ProjectID: projectID,
		Name:      "target only",
		Enabled:   true,
		Status:    "approved",
		Contexts:  []port.WaiverContext{{TargetID: target.ID}},
		Event:     port.WaiverEventInput{EventType: "created", Metadata: []byte(`{}`)},
	})
	require.NoError(t, err)

	contexts, err := stores.Waivers.ListContexts(ctx, waiver.ID)
	require.NoError(t, err)
	require.Len(t, contexts, 1)
	assert.Equal(t, "", contexts[0].EnvironmentID)
	assert.Equal(t, target.ID, contexts[0].TargetID)
	assert.Equal(t, "", contexts[0].ArtifactID)

	byWaiver, err := stores.Waivers.ListContextsByWaiverIDs(ctx, []string{waiver.ID})
	require.NoError(t, err)
	require.Len(t, byWaiver, 1)
	assert.Equal(t, "", byWaiver[0].EnvironmentID)
	assert.Equal(t, "", byWaiver[0].ArtifactID)
}
