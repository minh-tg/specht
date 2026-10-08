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

// linkScenario wires an account found by email plus a shared call log, so a
// test can assert the order in which the defence steps happen.
type linkScenario struct {
	calls   []string
	users   *mockUserRepo
	ids     *mockIdentityRepo
	tokens  *mockRefreshTokenRepo
	clearFn func(context.Context, string) error
	revokeF func(context.Context, string) error
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
		if s.clearFn != nil {
			return s.clearFn(ctx, id)
		}
		return nil
	}
	s.tokens = &mockRefreshTokenRepo{revokeAllFn: func(ctx context.Context, id string) error {
		s.calls = append(s.calls, "revoke:"+id)
		if s.revokeF != nil {
			return s.revokeF(ctx, id)
		}
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

func TestSSOLink_DisablesThePasswordAndRevokesSessionsBeforeLinking(t *testing.T) {
	s := newLinkScenario("hash-set-by-whoever-registered-first")

	err := s.login(t, verifiedClaims("sub-1", "victim@example.com"))

	require.NoError(t, err)
	assert.Equal(t, []string{"clear:user-1", "revoke:user-1", "link:user-1"}, s.calls,
		"stop password logins first, then kill existing sessions, then link")
}

func TestSSOLink_AccountWithoutAPasswordStillRevokesSessions(t *testing.T) {
	s := newLinkScenario("")

	err := s.login(t, verifiedClaims("sub-1", "victim@example.com"))

	require.NoError(t, err)
	assert.Equal(t, []string{"revoke:user-1", "link:user-1"}, s.calls,
		"nothing to clear, but a retry after a partial failure must still revoke")
}

func TestSSOLink_FailingToClearThePasswordFailsTheLogin(t *testing.T) {
	s := newLinkScenario("hash")
	s.clearFn = func(context.Context, string) error { return errors.New("db down") }

	err := s.login(t, verifiedClaims("sub-1", "victim@example.com"))

	require.Error(t, err)
	assert.NotErrorIs(t, err, auth.ErrSSONotProvisioned, "an infrastructure fault is not a policy refusal")
	assert.Equal(t, []string{"clear:user-1"}, s.calls, "no revoke and no link after a failed clear")
}

func TestSSOLink_FailingToRevokeSessionsFailsTheLogin(t *testing.T) {
	s := newLinkScenario("hash")
	s.revokeF = func(context.Context, string) error { return errors.New("db down") }

	err := s.login(t, verifiedClaims("sub-1", "victim@example.com"))

	require.Error(t, err)
	assert.Equal(t, []string{"clear:user-1", "revoke:user-1"}, s.calls, "the account must not be linked while old sessions live")
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
