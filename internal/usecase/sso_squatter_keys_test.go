package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

var squatterKeys = []port.RevokedAPIKey{
	{ID: "key-1", ProjectSlug: "squatted-app", Name: "ci"},
	{ID: "key-2", ProjectSlug: "squatted-app", Name: "deploy"},
}

// A person who registered the victim's address first may have minted keys
// before the victim's first SSO login. The link hands the account to the
// victim, so those keys must not outlive it.
func TestSSOLink_RevokesTheKeysTheSquatterCreated(t *testing.T) {
	s := newLinkScenario("hash-set-by-the-squatter")
	s.ids.keysByUser = map[string][]port.RevokedAPIKey{"user-1": squatterKeys}

	err := s.login(t, verifiedClaims("sub-1", "victim@example.com"))

	require.NoError(t, err)
	assert.Equal(t, squatterKeys, s.ids.revokedAtLink, "every key the account created is revoked by the link")
	assert.Empty(t, s.ids.keysByUser["user-1"])
	assert.Equal(t, []string{"link:user-1"}, s.calls,
		"the keys go with the link itself, not in a step that could be skipped")
}

func TestSSOLink_AccountWithoutAPasswordAlsoLosesItsKeys(t *testing.T) {
	s := newLinkScenario("")
	s.ids.keysByUser = map[string][]port.RevokedAPIKey{"user-1": squatterKeys}

	require.NoError(t, s.login(t, verifiedClaims("sub-1", "victim@example.com")))

	assert.Equal(t, squatterKeys, s.ids.revokedAtLink)
}

func TestSSOLink_ARefusedLinkLeavesTheKeys(t *testing.T) {
	s := newLinkScenario("hash")
	s.ids.keysByUser = map[string][]port.RevokedAPIKey{"user-1": squatterKeys}
	s.ids.linkErr = port.ErrIdentityLinked

	err := s.login(t, verifiedClaims("sub-1", "victim@example.com"))

	require.Error(t, err)
	assert.Empty(t, s.ids.revokedAtLink, "no link, no revocation")
	assert.Equal(t, squatterKeys, s.ids.keysByUser["user-1"])
}

func TestSSOLink_ReturningSubjectAndNewAccountsRevokeNoKeys(t *testing.T) {
	t.Run("returning subject", func(t *testing.T) {
		s := newLinkScenario("hash")
		s.ids.seed("user-1", ssoTestIssuer, "sub-1")
		s.ids.keysByUser = map[string][]port.RevokedAPIKey{"user-1": squatterKeys}
		s.users.getByIDFn = func(ctx context.Context, id string) (port.User, error) { return makeUser(id), nil }

		require.NoError(t, s.login(t, verifiedClaims("sub-1", "victim@example.com")))

		assert.Empty(t, s.ids.revokedAtLink, "a key made after the link belongs to the linked person")
	})

	t.Run("new account", func(t *testing.T) {
		s := newLinkScenario("")
		s.users.getByEmailFn = func(context.Context, string) (port.User, error) { return port.User{}, port.ErrNotFound }
		s.users.createFn = func(_ context.Context, email string, _, _ *string) (port.User, error) {
			u := makeUser("user-9")
			u.Email = email
			return u, nil
		}

		require.NoError(t, s.login(t, verifiedClaims("sub-9", "new@example.com")))

		assert.Empty(t, s.ids.revokedAtLink)
		assert.Len(t, s.ids.links, 1, "provisioning still links through the plain Link")
	})
}
