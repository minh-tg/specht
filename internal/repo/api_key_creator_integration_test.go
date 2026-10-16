//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// newKeyBy stores a key created by creator in project and returns its id and
// the hash a bearer would hash to.
func newKeyBy(t *testing.T, repos *Repos, project sqlc.Project, creator, name string) (id, hash string) {
	t.Helper()
	hash = "hash-" + uuid.NewString()
	row, err := repos.APIKeys.Create(context.Background(), sqlc.CreateAPIKeyParams{
		ProjectID: project.ID,
		Name:      name,
		KeyPrefix: "vuln_test",
		KeyHash:   hash,
		LastFour:  pgtype.Text{String: "0000", Valid: true},
		Scopes:    []byte(`["ingest","read"]`),
		CreatedBy: pgtype.UUID{Bytes: uuid.MustParse(creator), Valid: true},
	})
	require.NoError(t, err)
	return uuid.UUID(row.ID.Bytes).String(), hash
}

func keyRevoked(t *testing.T, repos *Repos, id string) bool {
	t.Helper()
	var revoked bool
	require.NoError(t, repos.pool.QueryRow(context.Background(),
		"SELECT revoked_at IS NOT NULL FROM api_keys WHERE id = $1", id).Scan(&revoked))
	return revoked
}

func TestDeactivateRevokesEveryKeyTheAccountCreated(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	admin := newUser(t, repos, "admin@test.com", "admin")
	leaver := newUser(t, repos, "leaver@test.com", "member")
	projectA := createTestProject(t, repos)
	projectB := createTestProject(t, repos)

	inA, _ := newKeyBy(t, repos, projectA, leaver.ID, "ci-a")
	inB, _ := newKeyBy(t, repos, projectB, leaver.ID, "ci-b")
	alreadyRevoked, _ := newKeyBy(t, repos, projectA, leaver.ID, "old")
	_, err := repos.pool.Exec(ctx, "UPDATE api_keys SET revoked_at = now() WHERE id = $1", alreadyRevoked)
	require.NoError(t, err)
	others, _ := newKeyBy(t, repos, projectA, admin.ID, "someone-elses")

	user, revoked, err := stores.Users.Deactivate(ctx, leaver.ID)
	require.NoError(t, err)
	require.NotNil(t, user.DisabledAt)

	assert.ElementsMatch(t, []port.RevokedAPIKey{
		{ID: inA, ProjectSlug: projectA.Slug, Name: "ci-a"},
		{ID: inB, ProjectSlug: projectB.Slug, Name: "ci-b"},
	}, revoked, "only the live keys the account created are reported")
	assert.True(t, keyRevoked(t, repos, inA))
	assert.True(t, keyRevoked(t, repos, inB))
	assert.False(t, keyRevoked(t, repos, others), "another person's key is left alone")

	again, revokedAgain, err := stores.Users.Deactivate(ctx, leaver.ID)
	require.NoError(t, err, "deactivating twice is harmless")
	assert.Empty(t, revokedAgain)
	assert.Equal(t, user.DisabledAt.Unix(), again.DisabledAt.Unix())

	reactivated, err := stores.Users.SetDisabled(ctx, leaver.ID, false)
	require.NoError(t, err)
	assert.Nil(t, reactivated.DisabledAt)
	assert.True(t, keyRevoked(t, repos, inA), "reactivating does not bring a key back")
	assert.True(t, keyRevoked(t, repos, inB))
}

func TestSetDisabledRevokesKeysToo(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "admin@test.com", "admin")
	leaver := newUser(t, repos, "leaver@test.com", "member")
	key, _ := newKeyBy(t, repos, createTestProject(t, repos), leaver.ID, "ci")

	_, err := stores.Users.SetDisabled(ctx, leaver.ID, true)
	require.NoError(t, err)
	assert.True(t, keyRevoked(t, repos, key), "no route to a deactivated account leaves its keys live")
}

func TestRefusedDeactivationRevokesNothing(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	only := newUser(t, repos, "only@test.com", "admin")
	key, _ := newKeyBy(t, repos, createTestProject(t, repos), only.ID, "ci")

	_, _, err := stores.Users.Deactivate(ctx, only.ID)
	require.ErrorIs(t, err, port.ErrLastGlobalAdmin)
	assert.False(t, keyRevoked(t, repos, key), "the refusal and the revocation are one transaction")
}

func TestKeyOfADeactivatedCreatorDoesNotResolve(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "admin@test.com", "admin")
	creator := newUser(t, repos, "creator@test.com", "member")
	_, hash := newKeyBy(t, repos, createTestProject(t, repos), creator.ID, "ci")

	_, err := stores.APIKeys.GetByHash(ctx, hash)
	require.NoError(t, err, "a key of an active creator resolves")

	// A key that survived a deactivation (a row written by another route, or a
	// revocation that never ran) must still not authenticate.
	_, err = repos.pool.Exec(ctx, "UPDATE users SET disabled_at = now() WHERE id = $1", creator.ID)
	require.NoError(t, err)
	_, err = stores.APIKeys.GetByHash(ctx, hash)
	require.ErrorIs(t, err, port.ErrNotFound, "port lookup")
	_, err = repos.APIKeys.GetByHash(ctx, hash)
	require.Error(t, err, "repository lookup")

	_, err = repos.pool.Exec(ctx, "UPDATE users SET disabled_at = NULL WHERE id = $1", creator.ID)
	require.NoError(t, err)
	_, err = stores.APIKeys.GetByHash(ctx, hash)
	require.NoError(t, err, "the check follows the account's current state")
}
