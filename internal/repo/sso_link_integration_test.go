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

const linkTestIssuer = "https://idp.example.com"

// squatter is an account whoever registered the address first holds: it has a
// password, a live refresh token, a pending reset link and an API key.
type squatter struct {
	resetFixture
	key string
}

func newSquatter(t *testing.T, repos *Repos) squatter {
	t.Helper()
	f := newResetFixture(t, repos, "victim@test.com")
	_, err := repos.pool.Exec(context.Background(),
		`INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, now() + interval '1 hour')`,
		f.user.ID, "rt-"+uuid.NewString())
	require.NoError(t, err)
	key, _ := newKeyBy(t, repos, createTestProject(t, repos), f.user.ID, "ci")
	return squatter{resetFixture: f, key: key}
}

func (s squatter) liveRefreshTokens(t *testing.T) int {
	t.Helper()
	var n int
	require.NoError(t, s.repos.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM refresh_tokens WHERE user_id = $1 AND revoked_at IS NULL", s.user.ID).Scan(&n))
	return n
}

func (s squatter) emailProven(t *testing.T) bool {
	t.Helper()
	var proven bool
	require.NoError(t, s.repos.pool.QueryRow(context.Background(),
		"SELECT email_proven FROM users WHERE id = $1", s.user.ID).Scan(&proven))
	return proven
}

// assertUntouched checks that the account still holds every credential the
// squatter gave it, which is what a refused or failed link must leave.
func (s squatter) assertUntouched(t *testing.T, tokenVersion int32) {
	t.Helper()
	ctx := context.Background()
	require.NotNil(t, s.passwordHash(t), "the password stays")
	got, err := s.stores.Users.TokenVersion(ctx, s.user.ID)
	require.NoError(t, err)
	assert.Equal(t, tokenVersion, got, "access tokens stay valid")
	assert.Equal(t, 1, s.liveRefreshTokens(t), "the refresh token stays")
	assert.Equal(t, 1, s.pendingLinks(t), "the reset link stays")
	assert.False(t, keyRevoked(t, s.repos, s.key), "the API key stays")
	_, err = s.stores.Identities.GetForUser(ctx, s.user.ID, linkTestIssuer)
	assert.ErrorIs(t, err, port.ErrNotFound, "no identity was linked")
	assert.False(t, s.emailProven(t))
}

func TestLinkRevokingKeysEndsEveryCredentialTheSquatterHolds(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newSquatter(t, repos)
	before, err := s.stores.Users.TokenVersion(ctx, s.user.ID)
	require.NoError(t, err)

	_, revoked, err := s.stores.Identities.LinkRevokingKeys(ctx, s.user.ID, linkTestIssuer, "sub-owner", true)
	require.NoError(t, err)

	require.Len(t, revoked, 1)
	assert.Equal(t, s.key, revoked[0].ID)
	assert.Nil(t, s.passwordHash(t), "the password is cleared")
	after, err := s.stores.Users.TokenVersion(ctx, s.user.ID)
	require.NoError(t, err)
	assert.Equal(t, before+1, after, "access tokens minted before the link stop working")
	assert.Equal(t, 0, s.liveRefreshTokens(t))
	assert.Equal(t, 0, s.pendingLinks(t))
	assert.True(t, keyRevoked(t, repos, s.key))
	assert.True(t, s.emailProven(t))
	linked, err := s.stores.Identities.GetForUser(ctx, s.user.ID, linkTestIssuer)
	require.NoError(t, err)
	assert.Equal(t, "sub-owner", linked.Subject)

	require.ErrorIs(t, s.redeem(t), port.ErrNotFound, "the squatter's reset link is dead")
	assert.Nil(t, s.passwordHash(t), "and the account stays password-less")
}

// The link is one transaction: a statement failing after the identity row was
// written leaves the account exactly as the squatter had it.
func TestLinkRevokingKeysRollsBackWhenALaterStatementFails(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newSquatter(t, repos)
	before, err := s.stores.Users.TokenVersion(ctx, s.user.ID)
	require.NoError(t, err)
	// The key revocation is the last statement of the link, so every other
	// write has happened by the time this one fails.
	_, err = repos.pool.Exec(ctx, `
		CREATE FUNCTION fail_key_revocation() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'injected failure'; END $$;
		CREATE TRIGGER fail_key_revocation BEFORE UPDATE ON api_keys
		FOR EACH ROW EXECUTE FUNCTION fail_key_revocation();`)
	require.NoError(t, err)

	_, _, err = s.stores.Identities.LinkRevokingKeys(ctx, s.user.ID, linkTestIssuer, "sub-owner", true)

	require.Error(t, err)
	assert.NotErrorIs(t, err, port.ErrIdentityLinked)
	s.assertUntouched(t, before)
}

func TestRefusedLinkLeavesTheSquattersCredentialsAlone(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newSquatter(t, repos)
	before, err := s.stores.Users.TokenVersion(ctx, s.user.ID)
	require.NoError(t, err)
	other := newTestUserID(t, repos)
	_, err = s.stores.Identities.Link(ctx, other, linkTestIssuer, "sub-taken", true)
	require.NoError(t, err)

	_, _, err = s.stores.Identities.LinkRevokingKeys(ctx, s.user.ID, linkTestIssuer, "sub-taken", true)

	require.ErrorIs(t, err, port.ErrIdentityLinked)
	s.assertUntouched(t, before)
}

// A squatter who redeems the old link at the moment the owner links must not
// end up with a password on the account, whichever transaction wins.
func TestLinkRacingARedeemNeverLeavesThePasswordBehind(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	s := newSquatter(t, repos)

	redeemed := make(chan error, 1)
	linked := make(chan error, 1)
	start := make(chan struct{})
	go func() { <-start; redeemed <- s.redeem(t) }()
	go func() {
		<-start
		_, _, err := s.stores.Identities.LinkRevokingKeys(ctx, s.user.ID, linkTestIssuer, "sub-owner", true)
		linked <- err
	}()
	close(start)
	rerr, lerr := <-redeemed, <-linked

	require.NoError(t, lerr)
	// Either the redeem won and the link then cleared the password it set, or the
	// link won and the redeem found a dead link.
	if rerr != nil {
		require.ErrorIs(t, rerr, port.ErrNotFound)
	}
	assert.Nil(t, s.passwordHash(t), "the account must end password-less")
	assert.Equal(t, 0, s.pendingLinks(t))
	assert.Eventually(t, func() bool { return s.liveRefreshTokens(t) == 0 }, time.Second, 10*time.Millisecond)
}
