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

func TestWatcherProjectFailure_CountsPerProjectAndClearsOnSuccess(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	create := func(slug string) port.Project {
		p, err := stores.Projects.Create(ctx, port.CreateProjectInput{
			Slug: slug, Name: slug, DeploymentThreshold: "high", Settings: []byte("{}"),
		})
		require.NoError(t, err)
		return p
	}
	broken, healthy := create("broken"), create("healthy")
	polledAt := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	require.NoError(t, stores.Watcher.UpsertProjectState(ctx, healthy.ID, polledAt))

	// A failure before any successful poll creates the row without a watermark.
	require.NoError(t, stores.Watcher.RecordProjectFailure(ctx, broken.ID, "osv: http 400"))
	require.NoError(t, stores.Watcher.RecordProjectFailure(ctx, broken.ID, "osv: http 400 again"))
	state, err := stores.Watcher.GetProjectState(ctx, broken.ID)
	require.NoError(t, err)
	assert.EqualValues(t, 2, state.ConsecutiveFailures)
	require.NotNil(t, state.LastError)
	assert.Equal(t, "osv: http 400 again", *state.LastError)
	assert.Nil(t, state.LastSuccessfulPollAt, "a failure never sets the watermark")

	other, err := stores.Watcher.GetProjectState(ctx, healthy.ID)
	require.NoError(t, err)
	assert.Zero(t, other.ConsecutiveFailures, "another project's failures stay on that project")
	assert.Nil(t, other.LastError)

	// A failure after a success keeps the watermark.
	require.NoError(t, stores.Watcher.RecordProjectFailure(ctx, healthy.ID, "timeout"))
	other, err = stores.Watcher.GetProjectState(ctx, healthy.ID)
	require.NoError(t, err)
	require.NotNil(t, other.LastSuccessfulPollAt)
	assert.True(t, polledAt.Equal(*other.LastSuccessfulPollAt))

	// A successful poll clears the failure state.
	require.NoError(t, stores.Watcher.UpsertProjectState(ctx, broken.ID, polledAt))
	state, err = stores.Watcher.GetProjectState(ctx, broken.ID)
	require.NoError(t, err)
	assert.Zero(t, state.ConsecutiveFailures)
	assert.Nil(t, state.LastError)
	require.NotNil(t, state.LastSuccessfulPollAt)
}
