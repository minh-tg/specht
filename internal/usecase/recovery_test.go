package usecase

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

type recoveryHarness struct {
	uc       *Usecases
	users    *mockUserRepo
	tokens   *mockRefreshTokenRepo
	lookedUp string
	stored   string
	revoked  []string
	verified []string
	promoted []string
}

func newRecoveryHarness(user port.User) *recoveryHarness {
	h := &recoveryHarness{users: &mockUserRepo{}, tokens: &mockRefreshTokenRepo{}}
	h.users.getByEmailFn = func(ctx context.Context, email string) (port.User, error) {
		h.lookedUp = email
		if user.ID == "" {
			return port.User{}, port.ErrNotFound
		}
		return user, nil
	}
	h.users.changePasswordFn = func(ctx context.Context, userID, hash, verifiedHash string) (int32, error) {
		h.stored = hash
		h.revoked = append(h.revoked, userID)
		h.verified = append(h.verified, verifiedHash)
		return 1, nil
	}
	h.users.changeRoleFn = func(ctx context.Context, userID, role string) (port.User, error) {
		h.promoted = append(h.promoted, userID+":"+role)
		user.Role = role
		return user, nil
	}
	h.uc = New(Deps{
		Stores:    &port.Stores{Users: h.users, RefreshTokens: h.tokens},
		Passwords: auth.NewPasswordHasher(),
	})
	return h
}

// recoveryExistingHash is the local password an account has before a reset.
const recoveryExistingHash = "$2a$10$existing-hash"

func recoveryUser(email, role string) port.User {
	u := makeUser("00000000-0000-0000-0000-000000000051")
	u.Email = email
	u.Role = role
	u.PasswordHash = recoveryExistingHash
	return u
}

func TestResetPasswordByEmail_SetsAHashAndEndsEverySession(t *testing.T) {
	h := newRecoveryHarness(recoveryUser("ada@acme.example", "admin"))

	reset, err := h.uc.ResetPasswordByEmail(context.Background(), "  Ada@Acme.Example ", "a-recovered-password", false)
	require.NoError(t, err)
	profile := reset.Profile
	assert.False(t, reset.WasSSOOnly)

	assert.Equal(t, "ada@acme.example", h.lookedUp, "the address is matched the way sign-in matches it")
	assert.True(t, auth.NewPasswordHasher().Verify("a-recovered-password", h.stored))
	assert.Equal(t, []string{"00000000-0000-0000-0000-000000000051"}, h.revoked)
	assert.Equal(t, []string{recoveryExistingHash}, h.verified,
		"the store checks the account still holds the password read here, so an SSO link in between cannot be undone")
	assert.Equal(t, "ada@acme.example", profile.Email)
}

func TestResetPasswordByEmail_ReportsADeactivatedAccountWithoutReactivatingIt(t *testing.T) {
	user := recoveryUser("ada@acme.example", "member")
	disabled := time.Now()
	user.DisabledAt = &disabled
	h := newRecoveryHarness(user)

	reset, err := h.uc.ResetPasswordByEmail(context.Background(), "ada@acme.example", "a-recovered-password", false)
	require.NoError(t, err)
	assert.True(t, reset.Profile.Disabled, "the caller is told the account still cannot sign in")
}

func TestResetPasswordByEmail_UnknownAccountChangesNothing(t *testing.T) {
	h := newRecoveryHarness(port.User{})

	_, err := h.uc.ResetPasswordByEmail(context.Background(), "nobody@acme.example", "a-recovered-password", false)
	assert.ErrorIs(t, err, ErrAccountNotFound)
	assert.Empty(t, h.stored)
}

func TestResetPasswordByEmail_TheSystemAccountIsOffLimits(t *testing.T) {
	h := newRecoveryHarness(recoveryUser("system@specht.local", "member"))

	_, err := h.uc.ResetPasswordByEmail(context.Background(), "system@specht.local", "a-recovered-password", false)
	assert.ErrorIs(t, err, ErrSystemAccount)
	assert.Empty(t, h.stored)
}

func TestResetPasswordByEmail_FollowsThePasswordRules(t *testing.T) {
	h := newRecoveryHarness(recoveryUser("ada@acme.example", "member"))

	_, err := h.uc.ResetPasswordByEmail(context.Background(), "ada@acme.example", "short", false)
	var input *credentialInputError
	assert.True(t, errors.As(err, &input), "%v", err)
	assert.Empty(t, h.stored)

	h.lookedUp = ""
	_, err = h.uc.ResetPasswordByEmail(context.Background(), "", "a-recovered-password", false)
	assert.Error(t, err, "an empty address is refused before any lookup")
	assert.Empty(t, h.lookedUp)
}

func TestResetPasswordByEmail_FailsClosedWhenTheChangeCannotCommit(t *testing.T) {
	h := newRecoveryHarness(recoveryUser("ada@acme.example", "member"))
	h.users.changePasswordFn = func(ctx context.Context, userID, hash, verifiedHash string) (int32, error) {
		return 0, errors.New("db down")
	}

	_, err := h.uc.ResetPasswordByEmail(context.Background(), "ada@acme.example", "a-recovered-password", false)
	require.Error(t, err)
	assert.Empty(t, h.stored, "the password and the session revoke commit together or not at all")
}

func TestGrantAdminByEmail_PromotesAMember(t *testing.T) {
	h := newRecoveryHarness(recoveryUser("ada@acme.example", "member"))

	profile, err := h.uc.GrantAdminByEmail(context.Background(), "Ada@acme.example")
	require.NoError(t, err)

	assert.Equal(t, []string{"00000000-0000-0000-0000-000000000051:admin"}, h.promoted,
		"ChangeRole starts a new token generation so open sessions pick the role up")
	assert.Equal(t, "admin", profile.Role)
}

func TestGrantAdminByEmail_AnAdminIsLeftAlone(t *testing.T) {
	h := newRecoveryHarness(recoveryUser("ada@acme.example", "admin"))

	profile, err := h.uc.GrantAdminByEmail(context.Background(), "ada@acme.example")
	require.NoError(t, err)
	assert.Empty(t, h.promoted)
	assert.Equal(t, "admin", profile.Role)
}

func TestGrantAdminByEmail_UnknownAndSystemAccountsAreRefused(t *testing.T) {
	missing := newRecoveryHarness(port.User{})
	_, err := missing.uc.GrantAdminByEmail(context.Background(), "nobody@acme.example")
	assert.ErrorIs(t, err, ErrAccountNotFound)

	system := newRecoveryHarness(recoveryUser("system@specht.local", "member"))
	_, err = system.uc.GrantAdminByEmail(context.Background(), "system@specht.local")
	assert.ErrorIs(t, err, ErrSystemAccount)
	assert.Empty(t, system.promoted)
}

func TestGrantAdminByEmail_RefusesADeactivatedAccount(t *testing.T) {
	disabled := recoveryUser("ada@acme.example", "member")
	at := time.Now()
	disabled.DisabledAt = &at
	h := newRecoveryHarness(disabled)

	_, err := h.uc.GrantAdminByEmail(context.Background(), "ada@acme.example")

	assert.ErrorIs(t, err, ErrAccountDeactivated)
	assert.Empty(t, h.promoted, "a deactivated account is not promoted")
}

func TestGrantAdminByEmail_MakesAnIdPGrantManual(t *testing.T) {
	granted := recoveryUser("ada@acme.example", "admin")
	granted.AdminSource = port.AdminSourceSSO
	h := newRecoveryHarness(granted)

	_, err := h.uc.GrantAdminByEmail(context.Background(), "ada@acme.example")
	require.NoError(t, err)
	assert.Equal(t, []string{"00000000-0000-0000-0000-000000000051:admin"}, h.promoted,
		"the store records the grant as manual, so a later SSO login cannot take it back")
}

func TestResetPasswordByEmail_RefusesAnSSOOnlyAccount(t *testing.T) {
	user := recoveryUser("ada@acme.example", "member")
	user.PasswordHash = ""
	h := newRecoveryHarness(user)

	_, err := h.uc.ResetPasswordByEmail(context.Background(), "ada@acme.example", "a-recovered-password", false)
	assert.ErrorIs(t, err, ErrNoLocalPassword, "the account signs in through the identity provider")
	assert.Empty(t, h.stored, "nothing is written")
}

func TestResetPasswordByEmail_TheOverrideGivesAnSSOOnlyAccountAPassword(t *testing.T) {
	user := recoveryUser("ada@acme.example", "member")
	user.PasswordHash = ""
	h := newRecoveryHarness(user)

	reset, err := h.uc.ResetPasswordByEmail(context.Background(), "ada@acme.example", "a-recovered-password", true)
	require.NoError(t, err)
	assert.True(t, reset.WasSSOOnly, "the caller is told the account now has a local password")
	assert.True(t, auth.NewPasswordHasher().Verify("a-recovered-password", h.stored))
	assert.Equal(t, []string{""}, h.verified, "there is no password to compare")
}

func TestResetPasswordByEmail_ALinkInBetweenIsNotUndone(t *testing.T) {
	h := newRecoveryHarness(recoveryUser("ada@acme.example", "member"))
	h.users.changePasswordFn = func(ctx context.Context, userID, hash, verifiedHash string) (int32, error) {
		return 0, port.ErrPasswordStale
	}

	_, err := h.uc.ResetPasswordByEmail(context.Background(), "ada@acme.example", "a-recovered-password", false)
	assert.ErrorIs(t, err, ErrRecoveryAccountChanged)
}
