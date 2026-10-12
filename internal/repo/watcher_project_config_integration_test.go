//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestWatcherProjectConfig_UpdateChangesOnlyWhatIsGiven(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "watched", Name: "Watched", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)

	before, err := stores.Watcher.GetProjectConfig(ctx, project.ID)
	require.NoError(t, err)
	assert.True(t, before.CveWatcherEnabled)
	assert.EqualValues(t, 3600, before.CveWatcherIntervalSecs)

	off := false
	updated, err := stores.Watcher.UpdateProjectConfig(ctx, project.ID, &off, nil)
	require.NoError(t, err)
	assert.False(t, updated.CveWatcherEnabled)
	assert.EqualValues(t, 3600, updated.CveWatcherIntervalSecs, "an omitted interval stays")

	seconds := int32(7200)
	updated, err = stores.Watcher.UpdateProjectConfig(ctx, project.ID, nil, &seconds)
	require.NoError(t, err)
	assert.False(t, updated.CveWatcherEnabled, "an omitted switch stays")
	assert.EqualValues(t, 7200, updated.CveWatcherIntervalSecs)

	on := true
	updated, err = stores.Watcher.UpdateProjectConfig(ctx, project.ID, &on, &seconds)
	require.NoError(t, err)
	assert.True(t, updated.CveWatcherEnabled)

	// The daemon's project list sees the change at its next reload.
	listed, err := stores.Projects.List(ctx)
	require.NoError(t, err)
	var found bool
	for _, p := range listed {
		if p.ID == project.ID {
			found = true
			assert.True(t, p.CveWatcherEnabled)
			assert.EqualValues(t, 7200, p.CveWatcherIntervalSecs)
		}
	}
	require.True(t, found)

	_, err = stores.Watcher.UpdateProjectConfig(ctx, "00000000-0000-4000-8000-000000000999", &on, nil)
	assert.ErrorIs(t, err, port.ErrNotFound)
}
