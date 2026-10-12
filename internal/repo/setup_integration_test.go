//go:build integration

package repo

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestCreateFirstAdmin_OnlyWhileNoAccountExists(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	users := NewPortStores(repos.pool).Users

	count, err := users.Count(ctx)
	require.NoError(t, err)
	assert.Zero(t, count)

	name := "Root"
	admin, err := users.CreateFirstAdmin(ctx, "root@example.com", &name, "$2a$10$hash")
	require.NoError(t, err)
	assert.Equal(t, "admin", admin.Role)
	assert.Equal(t, "root@example.com", admin.Email)

	_, err = users.CreateFirstAdmin(ctx, "second@example.com", nil, "$2a$10$hash")
	assert.ErrorIs(t, err, port.ErrSetupClosed)

	count, err = users.Count(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}

func TestCreateFirstAdmin_ClosedByAnyExistingAccount(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	newUser(t, repos, "early@example.com", "member")

	_, err := NewPortStores(repos.pool).Users.CreateFirstAdmin(context.Background(), "root@example.com", nil, "$2a$10$hash")

	assert.ErrorIs(t, err, port.ErrSetupClosed, "a registered member also closes setup")
}

func TestCreateFirstAdmin_RacingRequestsCreateOneAdmin(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	users := NewPortStores(repos.pool).Users

	const racers = 8
	results := make([]error, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := range racers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			email := "root" + string(rune('a'+i)) + "@example.com"
			_, results[i] = users.CreateFirstAdmin(ctx, email, nil, "$2a$10$hash")
		}()
	}
	close(start)
	wg.Wait()

	won := 0
	for _, err := range results {
		if err == nil {
			won++
			continue
		}
		assert.ErrorIs(t, err, port.ErrSetupClosed)
	}
	assert.Equal(t, 1, won, "exactly one request wins")
	count, err := users.Count(ctx)
	require.NoError(t, err)
	assert.EqualValues(t, 1, count)
}
