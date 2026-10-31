//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

func newKeyInput(projectID, creatorID, hash string) port.CreateAPIKeyInput {
	return port.CreateAPIKeyInput{
		ProjectID: projectID,
		Name:      "ci",
		KeyPrefix: "vuln_test",
		KeyHash:   hash,
		LastFour:  "0000",
		Scopes:    []byte(`["ingest","read"]`),
		CreatedBy: creatorID,
	}
}

func keyCount(t *testing.T, repos *Repos, hash string) int {
	t.Helper()
	var n int
	require.NoError(t, repos.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM api_keys WHERE key_hash = $1", hash).Scan(&n))
	return n
}

func TestCreateAPIKeyRefusesADeactivatedCreator(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "admin@test.com", "admin")
	creator := newUser(t, repos, "creator@test.com", "member")
	project := createTestProject(t, repos)
	_, _, err := stores.Users.Deactivate(ctx, creator.ID, true)
	require.NoError(t, err)

	_, err = stores.APIKeys.Create(ctx, newKeyInput(toUUID(project.ID), creator.ID, "hash-refused"))

	require.ErrorIs(t, err, port.ErrCreatorInactive)
	assert.Zero(t, keyCount(t, repos, "hash-refused"))
}

// The key insert holds a share lock on the creator's row for its transaction,
// which conflicts with the update a deactivation makes. A key request that
// passed authentication just before the deactivation therefore cannot commit
// after the deactivation revoked the creator's keys.
func TestCreateAPIKeyWaitsForAnInFlightDeactivation(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "admin@test.com", "admin")
	creator := newUser(t, repos, "creator@test.com", "member")
	project := createTestProject(t, repos)

	// The deactivation has updated the account and not committed yet.
	tx, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, "UPDATE users SET disabled_at = now() WHERE id = $1", creator.ID)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		_, err := stores.APIKeys.Create(ctx, newKeyInput(toUUID(project.ID), creator.ID, "hash-racing"))
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("the key was stored while the deactivation was still open: %v", err)
	case <-time.After(500 * time.Millisecond):
	}
	_, err = tx.Exec(ctx, "UPDATE api_keys SET revoked_at = now() WHERE created_by = $1", creator.ID)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	select {
	case err := <-done:
		require.ErrorIs(t, err, port.ErrCreatorInactive)
	case <-time.After(5 * time.Second):
		t.Fatal("the key request never finished after the deactivation committed")
	}
	assert.Zero(t, keyCount(t, repos, "hash-racing"), "no live key for a deactivated creator, now or after reactivation")
}

// The other order: a key insert that started first makes the deactivation wait,
// and the revocation that follows covers the new key.
func TestDeactivationWaitsForAnInFlightKeyInsert(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "admin@test.com", "admin")
	creator := newUser(t, repos, "creator@test.com", "member")
	project := createTestProject(t, repos)

	tx, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	_, err = q.LockKeyCreator(ctx, mustParseID(creator.ID))
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO api_keys (project_id, name, key_prefix, key_hash, scopes, created_by)
		VALUES ($1, 'ci', 'vuln_test', 'hash-inflight', '["ingest"]', $2)`, project.ID, creator.ID)
	require.NoError(t, err)

	type result struct {
		revoked []port.RevokedAPIKey
		err     error
	}
	done := make(chan result, 1)
	go func() {
		_, revoked, err := stores.Users.Deactivate(ctx, creator.ID, true)
		done <- result{revoked, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("the deactivation finished while a key insert was open: %v", r.err)
	case <-time.After(500 * time.Millisecond):
	}
	require.NoError(t, tx.Commit(ctx))

	select {
	case r := <-done:
		require.NoError(t, r.err)
		require.Len(t, r.revoked, 1, "the key inserted just before is revoked by the deactivation")
		assert.Equal(t, "ci", r.revoked[0].Name)
	case <-time.After(5 * time.Second):
		t.Fatal("the deactivation never finished after the insert committed")
	}
}
