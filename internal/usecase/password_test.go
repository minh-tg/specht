package usecase

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const passwordTestUserID = "00000000-0000-0000-0000-000000000040"

type passwordHarness struct {
	uc      *Usecases
	users   *mockUserRepo
	tokens  *mockRefreshTokenRepo
	stored  string
	hash    string
	version int
	revoked []string
	calls   []string
	// verified is the hash the usecase told the store the row must still hold.
	verified string
}

func newPasswordHarness(t *testing.T, currentPassword string) *passwordHarness {
	t.Helper()
	h := &passwordHarness{users: &mockUserRepo{}, tokens: &mockRefreshTokenRepo{}}
	hash := ""
	if currentPassword != "" {
		var err error
		hash, err = auth.HashPassword(currentPassword)
		require.NoError(t, err)
	}
	h.users.getByIDFn = func(ctx context.Context, id string) (port.User, error) {
		u := makeUser(id)
		u.PasswordHash = hash
		return u, nil
	}
	h.hash = hash
	h.users.changePasswordFn = func(ctx context.Context, userID, passwordHash, verifiedHash string) (int32, error) {
		h.calls = append(h.calls, "change-password")
		h.stored = passwordHash
		h.verified = verifiedHash
		h.version++
		h.revoked = append(h.revoked, userID)
		return int32(h.version), nil
	}
	h.tokens.createFn = func(ctx context.Context, in port.NewRefreshToken) (port.RefreshToken, error) {
		h.calls = append(h.calls, "create-session")
		return makeRefreshToken(false), nil
	}
	h.uc = New(Deps{
		Stores:    &port.Stores{Users: h.users, RefreshTokens: h.tokens},
		Tokens:    testJWT(t),
		Passwords: auth.NewPasswordHasher(),
	})
	return h
}

func TestChangePassword_ReplacesTheHashAndEndsOtherSessions(t *testing.T) {
	h := newPasswordHarness(t, "correct-password")

	resp, err := h.uc.ChangePassword(context.Background(), passwordTestUserID, "correct-password", "a-new-password")
	require.NoError(t, err)

	require.NotEmpty(t, h.stored, "the new hash is stored")
	assert.True(t, auth.NewPasswordHasher().Verify("a-new-password", h.stored))
	assert.False(t, auth.NewPasswordHasher().Verify("correct-password", h.stored))
	assert.Equal(t, []string{passwordTestUserID}, h.revoked)
	assert.Equal(t, []string{"change-password", "create-session"}, h.calls,
		"the hash, the new token generation and the revoke are one store call, and the caller's new session is last")
	assert.Equal(t, 1, h.version, "a successful change starts exactly one new token generation")
	assert.Equal(t, h.hash, h.verified, "the store is told which hash was verified, so a change that landed first is detected")

	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token, "the caller stays signed in with a fresh session")
	assert.NotEmpty(t, resp.RefreshToken)
	assert.Equal(t, passwordTestUserID, resp.UserID)
}

func TestChangePassword_WrongCurrentPasswordChangesNothing(t *testing.T) {
	h := newPasswordHarness(t, "correct-password")

	_, err := h.uc.ChangePassword(context.Background(), passwordTestUserID, "not-it-at-all", "a-new-password")
	assert.ErrorIs(t, err, ErrWrongPassword)
	assert.Empty(t, h.calls, "no write, no revoke")
}

func TestChangePassword_AccountWithoutAPasswordIsRefused(t *testing.T) {
	h := newPasswordHarness(t, "")

	_, err := h.uc.ChangePassword(context.Background(), passwordTestUserID, "anything-here", "a-new-password")
	assert.ErrorIs(t, err, ErrNoLocalPassword, "an SSO-only account signs in through its provider")
	assert.Empty(t, h.calls)
}

func TestChangePassword_NewPasswordFollowsTheRegistrationRules(t *testing.T) {
	cases := map[string]string{
		"too short": "short",
		"too long":  strings.Repeat("x", 73),
		"empty":     "",
		"unchanged": "correct-password",
	}
	for name, next := range cases {
		t.Run(name, func(t *testing.T) {
			h := newPasswordHarness(t, "correct-password")
			_, err := h.uc.ChangePassword(context.Background(), passwordTestUserID, "correct-password", next)
			require.Error(t, err)
			var input *credentialInputError
			assert.True(t, errors.As(err, &input), "rule violations are input errors the handler can show: %v", err)
			assert.Empty(t, h.calls)
		})
	}
}

func TestChangePassword_FailsClosedWhenTheChangeCannotCommit(t *testing.T) {
	h := newPasswordHarness(t, "correct-password")
	h.users.changePasswordFn = func(ctx context.Context, userID, passwordHash, verifiedHash string) (int32, error) {
		h.calls = append(h.calls, "change-password")
		return 0, errors.New("db down")
	}

	_, err := h.uc.ChangePassword(context.Background(), passwordTestUserID, "correct-password", "a-new-password")
	require.Error(t, err)
	assert.Equal(t, []string{"change-password"}, h.calls, "no session is created for a change that did not commit")
	assert.Empty(t, h.stored)
}

func TestChangePassword_AHashThatChangedSinceTheCheckCountsAsWrong(t *testing.T) {
	h := newPasswordHarness(t, "correct-password")
	h.users.changePasswordFn = func(ctx context.Context, userID, passwordHash, verifiedHash string) (int32, error) {
		h.calls = append(h.calls, "change-password")
		return 0, port.ErrPasswordStale
	}

	_, err := h.uc.ChangePassword(context.Background(), passwordTestUserID, "correct-password", "a-new-password")
	assert.ErrorIs(t, err, ErrWrongPassword, "a reset or an SSO link replaced the hash the caller proved")
	assert.Equal(t, []string{"change-password"}, h.calls, "no session is created for a change that wrote nothing")
}

func TestChangePassword_StoresTheCallersSessionAgainstTheNewHashAndGeneration(t *testing.T) {
	h := newPasswordHarness(t, "correct-password")
	var guard port.LoginGuard
	h.tokens.createForLoginFn = func(_ context.Context, _ port.NewRefreshToken, g port.LoginGuard) (int32, error) {
		h.calls = append(h.calls, "create-session")
		guard = g
		return g.TokenVersion, nil
	}

	resp, err := h.uc.ChangePassword(context.Background(), passwordTestUserID, "correct-password", "a-new-password")
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, h.stored, guard.PasswordHash, "the store refuses the session if the hash the change wrote is gone")
	assert.EqualValues(t, h.version, guard.TokenVersion, "the store refuses the session if the generation the change started moved")
	identity, err := testJWT(t).Authenticate(context.Background(), resp.Token)
	require.NoError(t, err)
	require.NotNil(t, identity.TokenVersion)
	assert.EqualValues(t, h.version, *identity.TokenVersion, "the access token carries the generation the change started")
}

func TestChangePassword_AnAccountChangeBeforeTheCallersSessionRefusesTheSession(t *testing.T) {
	h := newPasswordHarness(t, "correct-password")
	h.tokens.createForLoginFn = func(context.Context, port.NewRefreshToken, port.LoginGuard) (int32, error) {
		h.calls = append(h.calls, "create-session")
		return 0, port.ErrLoginStale
	}

	resp, err := h.uc.ChangePassword(context.Background(), passwordTestUserID, "correct-password", "a-new-password")
	assert.ErrorIs(t, err, ErrAccountChanged, "an SSO link or another change landed between the change and the session")
	assert.Nil(t, resp, "no token is issued for a generation that has already ended")
}

func TestChangePassword_RejectsAnInvalidUserID(t *testing.T) {
	h := newPasswordHarness(t, "correct-password")

	_, err := h.uc.ChangePassword(context.Background(), "not-a-uuid", "correct-password", "a-new-password")
	assert.ErrorIs(t, err, ErrInvalidID)
}
