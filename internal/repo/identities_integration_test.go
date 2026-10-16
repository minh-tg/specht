//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentities_LinkLookupAndUniqueness(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	ids := &pgIdentityPort{q: sqlc.New(repos.pool)}
	const issuer = "https://idp.example.com"

	alice := newTestUserID(t, repos)
	bob := newTestUserID(t, repos)

	_, err := ids.GetBySubject(ctx, issuer, "sub-alice")
	assert.ErrorIs(t, err, port.ErrNotFound, "an unlinked subject is not found")
	_, err = ids.GetForUser(ctx, alice, issuer)
	assert.ErrorIs(t, err, port.ErrNotFound)

	linked, err := ids.Link(ctx, alice, issuer, "sub-alice", false)
	require.NoError(t, err)
	assert.Equal(t, alice, linked.UserID)
	assert.Equal(t, issuer, linked.Issuer)
	assert.Equal(t, "sub-alice", linked.Subject)

	found, err := ids.GetBySubject(ctx, issuer, "sub-alice")
	require.NoError(t, err)
	assert.Equal(t, alice, found.UserID)
	byUser, err := ids.GetForUser(ctx, alice, issuer)
	require.NoError(t, err)
	assert.Equal(t, "sub-alice", byUser.Subject)

	_, err = ids.Link(ctx, bob, issuer, "sub-alice", false)
	assert.ErrorIs(t, err, port.ErrIdentityLinked, "one provider identity cannot belong to two accounts")
	_, err = ids.Link(ctx, alice, issuer, "sub-other", false)
	assert.ErrorIs(t, err, port.ErrIdentityLinked, "an account has at most one identity per provider")

	other, err := ids.Link(ctx, bob, "https://other-idp.example.com", "sub-alice", false)
	require.NoError(t, err, "the same subject string at a different provider is a different identity")
	assert.Equal(t, bob, other.UserID)
}

func TestIdentities_RemovedWithTheirAccount(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	ids := &pgIdentityPort{q: sqlc.New(repos.pool)}

	user := newTestUserID(t, repos)
	_, err := ids.Link(ctx, user, "https://idp.example.com", "sub-gone", false)
	require.NoError(t, err)

	_, err = repos.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, uuid.MustParse(user))
	require.NoError(t, err)

	_, err = ids.GetBySubject(ctx, "https://idp.example.com", "sub-gone")
	assert.ErrorIs(t, err, port.ErrNotFound, "deleting an account must not leave its identity behind")
}

func TestIdentities_LinkRecordsAProvenEmail(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	const issuer = "https://idp.example.com"

	registered := newTestUserID(t, repos)
	optIn := newTestUserID(t, repos)
	verified := newTestUserID(t, repos)

	proven := func(id string) bool {
		t.Helper()
		u, err := stores.Users.GetByID(ctx, id)
		require.NoError(t, err)
		return u.EmailProven
	}
	assert.False(t, proven(registered), "a registered account has proven nothing")

	_, err := stores.Identities.Link(ctx, optIn, issuer, "sub-opt-in", false)
	require.NoError(t, err)
	assert.False(t, proven(optIn), "a link under the unverified-email opt-in does not prove the address")

	_, err = stores.Identities.Link(ctx, verified, issuer, "sub-verified", true)
	require.NoError(t, err)
	assert.True(t, proven(verified), "a link where the provider vouched for the email proves it")

	_, err = stores.Identities.Link(ctx, registered, issuer, "sub-verified", true)
	assert.ErrorIs(t, err, port.ErrIdentityLinked)
	assert.False(t, proven(registered), "a refused link must not mark the account")
}
