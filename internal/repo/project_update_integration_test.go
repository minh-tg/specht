//go:build integration

package repo

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// Two updates of different fields at once keep both. The statement writes only
// the fields it was given, so the second one applies to the row the first left.
func TestProjectUpdate_ConcurrentUpdatesOfDifferentFieldsKeepBoth(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)

	for round := 0; round < 25; round++ {
		slug := fmt.Sprintf("race-%d", round)
		_, err := stores.Projects.Create(ctx, port.CreateProjectInput{
			Slug: slug, Name: "Original", Description: "original description", DeploymentThreshold: "high", Settings: []byte("{}"),
		})
		require.NoError(t, err)

		name, desc, branch := fmt.Sprintf("Renamed %d", round), fmt.Sprintf("described %d", round), "trunk"
		changes := []port.ProjectUpdate{
			{Name: &name},
			{SetDescription: true, Description: &desc},
			{SetDefaultBranch: true, DefaultBranch: &branch},
		}
		var wg sync.WaitGroup
		errs := make([]error, len(changes))
		start := make(chan struct{})
		for i := range changes {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[i] = stores.Projects.Update(ctx, slug, changes[i])
			}()
		}
		close(start)
		wg.Wait()
		for _, err := range errs {
			require.NoError(t, err)
		}

		got, err := stores.Projects.GetBySlug(ctx, slug)
		require.NoError(t, err)
		assert.Equal(t, name, got.Name, "round %d", round)
		require.NotNil(t, got.Description, "round %d", round)
		assert.Equal(t, desc, *got.Description, "round %d", round)
		require.NotNil(t, got.DefaultBranch, "round %d", round)
		assert.Equal(t, branch, *got.DefaultBranch, "round %d", round)
	}
}

func TestProjectUpdate_OmittedFieldsStayAndSetFieldsCanClear(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	_, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "partial", Name: "Partial", Description: "kept", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	branch := "main"
	_, err = stores.Projects.Update(ctx, "partial", port.ProjectUpdate{SetDefaultBranch: true, DefaultBranch: &branch})
	require.NoError(t, err)

	renamed := "Renamed"
	got, err := stores.Projects.Update(ctx, "partial", port.ProjectUpdate{Name: &renamed})
	require.NoError(t, err)
	assert.Equal(t, "Renamed", got.Name)
	require.NotNil(t, got.Description)
	assert.Equal(t, "kept", *got.Description, "an omitted description stays")
	require.NotNil(t, got.DefaultBranch)
	assert.Equal(t, "main", *got.DefaultBranch, "an omitted default branch stays")

	got, err = stores.Projects.Update(ctx, "partial", port.ProjectUpdate{SetDescription: true})
	require.NoError(t, err)
	assert.Nil(t, got.Description, "a set description with no value clears it")
	assert.Equal(t, "Renamed", got.Name)

	_, err = stores.Projects.Update(ctx, "missing", port.ProjectUpdate{Name: &renamed})
	assert.ErrorIs(t, err, port.ErrNotFound)
}
