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
	uc     *Usecases
	users  *mockUserRepo
	tokens *mockRefreshTokenRepo
	stored string
	calls  []string
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
	h.users.setPasswordFn = func(ctx context.Context, userID, passwordHash string) error {
		h.calls = append(h.calls, "set-password")
		h.stored = passwordHash
		return nil
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
	assert.Equal(t, []string{"set-password", "create-session"}, h.calls,
		"the write ends the old sessions in its own transaction, so the caller's new session comes after it")

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

func TestChangePassword_FailsClosedWhenThePasswordCannotBeStored(t *testing.T) {
	h := newPasswordHarness(t, "correct-password")
	h.users.setPasswordFn = func(ctx context.Context, userID, passwordHash string) error {
		h.calls = append(h.calls, "set-password")
		return errors.New("db down")
	}

	_, err := h.uc.ChangePassword(context.Background(), passwordTestUserID, "correct-password", "a-new-password")
	require.Error(t, err)
	assert.Equal(t, []string{"set-password"}, h.calls, "no session is issued for a password that was not stored")
}

func TestChangePassword_RejectsAnInvalidUserID(t *testing.T) {
	h := newPasswordHarness(t, "correct-password")

	_, err := h.uc.ChangePassword(context.Background(), "not-a-uuid", "correct-password", "a-new-password")
	assert.ErrorIs(t, err, ErrInvalidID)
}
