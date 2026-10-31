//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestIngestTransactionRefusesAKeyThatIsNoLongerLive(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "admin@test.com", "admin")
	project := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()
	runs := func(hash string) (entered bool, err error) {
		err = stores.Ingest.Run(ctx, projectID, hash, func(*port.Stores) error {
			entered = true
			return nil
		})
		return entered, err
	}

	creator := newUser(t, repos, "creator@test.com", "member")
	_, live := newKeyBy(t, repos, project, creator.ID, "live")
	entered, err := runs(live)
	require.NoError(t, err)
	assert.True(t, entered, "a live key writes")
	entered, err = runs("")
	require.NoError(t, err)
	assert.True(t, entered, "a caller without a key is not checked")

	revoked, revokedHash := newKeyBy(t, repos, project, creator.ID, "revoked")
	_, err = repos.pool.Exec(ctx, "UPDATE api_keys SET revoked_at = now() WHERE id = $1", revoked)
	require.NoError(t, err)
	entered, err = runs(revokedHash)
	require.ErrorIs(t, err, port.ErrAPIKeyInactive)
	assert.False(t, entered, "a revoked key does not write")

	// A key that slipped past revocation still stops with its creator.
	gone := newUser(t, repos, "gone@test.com", "member")
	_, orphanHash := newKeyBy(t, repos, project, gone.ID, "orphan")
	_, err = repos.pool.Exec(ctx, "UPDATE users SET disabled_at = now() WHERE id = $1", gone.ID)
	require.NoError(t, err)
	entered, err = runs(orphanHash)
	require.ErrorIs(t, err, port.ErrAPIKeyInactive)
	assert.False(t, entered, "a key of a deactivated creator does not write")

	_, err = runs("hash-nobody-minted")
	require.ErrorIs(t, err, port.ErrAPIKeyInactive)
}

// A deactivation that starts while an ingest holds the key waits for it, then
// revokes the key. The ingest therefore finishes before the deactivation takes
// effect, and no ingest starts after it.
func TestDeactivationWaitsForAnIngestHoldingTheKey(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "admin@test.com", "admin")
	creator := newUser(t, repos, "creator@test.com", "member")
	project := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()
	keyID, hash := newKeyBy(t, repos, project, creator.ID, "ci")

	entered, release, ingested := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	go func() {
		ingested <- stores.Ingest.Run(ctx, projectID, hash, func(*port.Stores) error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	deactivated := make(chan error, 1)
	go func() {
		_, _, err := stores.Users.Deactivate(ctx, creator.ID, true)
		deactivated <- err
	}()
	select {
	case err := <-deactivated:
		t.Fatalf("the deactivation finished while an ingest held the key: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	assert.False(t, keyRevoked(t, repos, keyID))

	close(release)
	require.NoError(t, <-ingested)
	select {
	case err := <-deactivated:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the deactivation never finished after the ingest committed")
	}
	assert.True(t, keyRevoked(t, repos, keyID))

	err := stores.Ingest.Run(ctx, projectID, hash, func(*port.Stores) error {
		t.Error("an ingest started after the deactivation")
		return nil
	})
	require.ErrorIs(t, err, port.ErrAPIKeyInactive)
}
