package usecase

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// linkScenario wires an account found by email plus a shared call log. The
// user and refresh-token mocks fail any call that is not stubbed, so a test
// also proves the use case no longer reaches for those stores on a link: the
// identity store ends every credential in the link's own transaction.
type linkScenario struct {
	calls  []string
	users  *mockUserRepo
	ids    *mockIdentityRepo
	tokens *mockRefreshTokenRepo
}

func newLinkScenario(passwordHash string) *linkScenario {
	s := &linkScenario{ids: newMockIdentityRepo()}
	s.ids.onLink = func(userID string) { s.calls = append(s.calls, "link:"+userID) }
	s.users = &mockUserRepo{}
	s.users.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		u := makeUser("user-1")
		u.Email = email
		u.PasswordHash = passwordHash
		return u, nil
	}
	s.users.clearPasswordFn = func(ctx context.Context, id string) error {
		s.calls = append(s.calls, "clear:"+id)
		return nil
	}
	s.users.bumpTokenVersionFn = func(ctx context.Context, id string) error {
		s.calls = append(s.calls, "bump:"+id)
		return nil
	}
	s.tokens = &mockRefreshTokenRepo{revokeAllFn: func(ctx context.Context, id string) error {
		s.calls = append(s.calls, "revoke:"+id)
		return nil
	}}
	return s
}

func (s *linkScenario) login(t *testing.T, claims auth.SSOClaims) error {
	t.Helper()
	deps := Deps{Stores: &port.Stores{Users: s.users, Identities: s.ids, RefreshTokens: s.tokens}}
	_, _, _, err := New(deps).FindOrProvisionSSOUser(context.Background(), claims, []string{"example.com"}, nil)
	return err
}

func TestSSOLink_EndsTheOldCredentialsInTheLinkTransactionOnly(t *testing.T) {
	for name, hash := range map[string]string{
		"an account with a password":    "hash-set-by-whoever-registered-first",
		"an account without a password": "",
	} {
		s := newLinkScenario(hash)

		err := s.login(t, verifiedClaims("sub-1", "victim@example.com"))

		require.NoError(t, err, name)
		assert.Equal(t, []string{"link:user-1"}, s.calls,
			name+": one store call does the whole takeover; separate calls could be left half done")
	}
}

func TestSSOLink_AFailedLinkFailsTheLoginAsAFault(t *testing.T) {
	s := newLinkScenario("hash")
	s.ids.linkErr = errors.New("db down")

	err := s.login(t, verifiedClaims("sub-1", "victim@example.com"))

	require.Error(t, err)
	assert.NotErrorIs(t, err, auth.ErrSSONotProvisioned, "an infrastructure fault is not a policy refusal")
	assert.Empty(t, s.calls, "nothing else was touched, so the next login starts over")
}

func TestSSOLink_ProvisioningANewAccountTouchesNoPasswordOrSessions(t *testing.T) {
	s := newLinkScenario("")
	s.users.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}
	s.users.createFn = func(ctx context.Context, email string, displayName, passwordHash *string) (port.User, error) {
		u := makeUser("user-9")
		u.Email = email
		u.Role = "member"
		return u, nil
	}

	err := s.login(t, verifiedClaims("sub-9", "new@example.com"))

	require.NoError(t, err)
	assert.Equal(t, []string{"link:user-9"}, s.calls)
}

func TestSSOLink_ReturningLinkedSubjectTouchesNoPasswordOrSessions(t *testing.T) {
	s := newLinkScenario("hash")
	s.ids.seed("user-1", ssoTestIssuer, "sub-1")
	s.users.getByIDFn = func(ctx context.Context, id string) (port.User, error) {
		return makeUser(id), nil
	}

	err := s.login(t, verifiedClaims("sub-1", "victim@example.com"))

	require.NoError(t, err)
	assert.Empty(t, s.calls, "only the first link disables the password")
}
