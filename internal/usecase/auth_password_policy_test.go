package usecase

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// The two policy errors stay credential input errors, so every caller that
// already reports ErrInvalidCredentialInput (the recovery command among them)
// keeps showing their message.
func TestPasswordPolicyErrorsAreCredentialInputErrors(t *testing.T) {
	for _, err := range []error{ErrPasswordTooCommon, ErrPasswordMatchesAccount, ErrPasswordNotVisible} {
		assert.ErrorIs(t, err, ErrInvalidCredentialInput, err.Error())
	}
	assert.NotErrorIs(t, ErrPasswordTooCommon, ErrPasswordMatchesAccount)
	assert.NotErrorIs(t, ErrPasswordNotVisible, ErrPasswordTooCommon)
	assert.NotErrorIs(t, ErrPasswordNotVisible, ErrPasswordMatchesAccount)
}

func TestCheckPassword(t *testing.T) {
	cases := []struct {
		name, password, email, display string
		want                           error
	}{
		{"listed", "password1", "ada@acme.example", "", ErrPasswordTooCommon},
		{"listed in capitals", "PASSWORD1", "ada@acme.example", "", ErrPasswordTooCommon},
		{"whole email", "Ada@Acme.Example", "ada@acme.example", "", ErrPasswordMatchesAccount},
		{"local part", "ada.lovelace", "ada.lovelace@acme.example", "", ErrPasswordMatchesAccount},
		{"display name", "Ada Lovelace", "x@acme.example", "Ada Lovelace", ErrPasswordMatchesAccount},
		{"eight spaces", "        ", "ada@acme.example", "", ErrPasswordNotVisible},
		{"eight zero-width spaces", strings.Repeat("\u200b", 8), "ada@acme.example", "", ErrPasswordNotVisible},
		{"eight combining marks", strings.Repeat("\u0301", 8), "ada@acme.example", "", ErrPasswordNotVisible},
		{"listed with a zero-width space", "pass\u200bword1", "ada@acme.example", "", ErrPasswordTooCommon},
		{"listed with a soft hyphen", "pass\u00adword1", "ada@acme.example", "", ErrPasswordTooCommon},
		{"email with a zero-width space", "ada\u200b@acme.example", "ada@acme.example", "", ErrPasswordMatchesAccount},
		{"unlisted", "a-long-unrelated-phrase", "ada@acme.example", "Ada", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkPassword(tc.password, tc.email, tc.display)
			if tc.want == nil {
				assert.NoError(t, err)
				return
			}
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

func TestRegister_RefusesAListedPassword(t *testing.T) {
	uc := New(Deps{})
	_, err := uc.Register(context.Background(), "ada@acme.example", "password1")
	assert.ErrorIs(t, err, ErrPasswordTooCommon)

	_, err = uc.Register(context.Background(), "ada.lovelace@acme.example", "Ada.Lovelace")
	assert.ErrorIs(t, err, ErrPasswordMatchesAccount)
}

// Register answers a duplicate email with the generic ErrRegistrationFailed so
// the endpoint reveals nobody's account. The password rules run before the
// lookup, so a listed password is refused for every address alike and its
// specific error says nothing about who is registered.
func TestRegister_PasswordRulesRunBeforeTheDuplicateLookup(t *testing.T) {
	looked := false
	ur := &mockUserRepo{getByEmailFn: func(ctx context.Context, email string) (port.User, error) {
		looked = true
		return makeUser("00000000-0000-0000-0000-000000000041"), nil
	}}
	uc := New(Deps{Stores: &port.Stores{Users: ur}})

	_, err := uc.Register(context.Background(), "test@example.com", "password1")
	assert.ErrorIs(t, err, ErrPasswordTooCommon)
	assert.False(t, looked, "a refused password never reaches the account lookup")

	_, err = uc.Register(context.Background(), "test@example.com", "a-long-unrelated-phrase")
	assert.ErrorIs(t, err, ErrRegistrationFailed, "a duplicate with a good password stays generic")
	assert.NotErrorIs(t, err, ErrInvalidCredentialInput)
}

func TestSetup_RefusesAListedOrAccountPassword(t *testing.T) {
	for name, tc := range map[string]struct {
		in   SetupInput
		want error
	}{
		"listed":       {SetupInput{Email: "a@example.com", Password: "password1"}, ErrPasswordTooCommon},
		"email":        {SetupInput{Email: "root@example.com", Password: "ROOT@example.com"}, ErrPasswordMatchesAccount},
		"display name": {SetupInput{Email: "a@example.com", Password: "Grace Hopper", DisplayName: " Grace Hopper "}, ErrPasswordMatchesAccount},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t, 0)
			tc.in.Token = "s3cret-token-0123456789"

			_, err := f.uc.Setup(context.Background(), tc.in)

			assert.ErrorIs(t, err, tc.want)
			assert.Empty(t, f.created)
			assert.Equal(t, "s3cret-token-0123456789", f.token.Value(), "a refused password does not burn the token")
		})
	}
}

func TestAcceptInvite_RefusesAListedOrAccountPasswordBeforeTouchingTheLink(t *testing.T) {
	f := newInviteTestFixture(t, "manager")
	created, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member"})
	require.NoError(t, err)
	token := strings.TrimPrefix(created.Link, "/invite/")

	for name, tc := range map[string]struct {
		in   AcceptInviteInput
		want error
	}{
		"listed":       {AcceptInviteInput{Email: "a@example.com", Password: "password1"}, ErrPasswordTooCommon},
		"local part":   {AcceptInviteInput{Email: "newcomer.one@example.com", Password: "newcomer.one"}, ErrPasswordMatchesAccount},
		"display name": {AcceptInviteInput{Email: "a@example.com", Password: "Linus Pauling", DisplayName: "Linus Pauling"}, ErrPasswordMatchesAccount},
	} {
		_, err := f.uc.AcceptInvite(context.Background(), token, tc.in)
		assert.ErrorIs(t, err, tc.want, name)
	}
	_, err = f.uc.LookupInvite(context.Background(), token)
	assert.NoError(t, err, "a refused password does not use up the link")
}

func TestChangePassword_RefusesAListedOrAccountPassword(t *testing.T) {
	for name, tc := range map[string]struct {
		next string
		want error
	}{
		"listed": {"password1", ErrPasswordTooCommon},
		"email":  {"Test@Example.com", ErrPasswordMatchesAccount},
	} {
		t.Run(name, func(t *testing.T) {
			h := newPasswordHarness(t, "correct-password")
			_, err := h.uc.ChangePassword(context.Background(), passwordTestUserID, "correct-password", tc.next)
			assert.ErrorIs(t, err, tc.want)
			assert.Empty(t, h.calls, "no write, no revoke")
		})
	}
}

// An SSO-only account has no local password to change, so it learns that
// before any rule about the new password; a listed one does not hide it.
func TestChangePassword_NoLocalPasswordComesBeforeThePolicy(t *testing.T) {
	h := newPasswordHarness(t, "")
	_, err := h.uc.ChangePassword(context.Background(), passwordTestUserID, "anything", "password1")
	assert.ErrorIs(t, err, ErrNoLocalPassword)
	assert.NotErrorIs(t, err, ErrPasswordTooCommon)
	assert.Empty(t, h.calls)
}

// The account is compared after it is loaded, so a password equal to the
// stored display name is refused too.
func TestChangePassword_ComparesWithTheStoredDisplayName(t *testing.T) {
	h := newPasswordHarness(t, "correct-password")
	loaded := h.users.getByIDFn
	name := "Rosalind Franklin"
	h.users.getByIDFn = func(ctx context.Context, id string) (port.User, error) {
		u, err := loaded(ctx, id)
		u.DisplayName = &name
		return u, err
	}

	_, err := h.uc.ChangePassword(context.Background(), passwordTestUserID, "correct-password", "rosalind franklin")
	assert.ErrorIs(t, err, ErrPasswordMatchesAccount)
	assert.Empty(t, h.calls)
}

// A reset link does not say whose account it is until the store spends it, so
// only the list and the length rules apply here.
func TestRedeemPasswordReset_RefusesAListedPasswordBeforeSpendingTheLink(t *testing.T) {
	uc, store := resetHarness(localUser())

	err := uc.RedeemPasswordReset(context.Background(), "tok-123", "Password1")
	assert.ErrorIs(t, err, ErrPasswordTooCommon)
	assert.Empty(t, store.redeemedHash, "a refused password must leave the link unused")
}

func TestResetPasswordByEmail_RefusesAListedOrAccountPassword(t *testing.T) {
	for name, tc := range map[string]struct {
		password string
		want     error
	}{
		"listed":     {"password1", ErrPasswordTooCommon},
		"local part": {"ada.lovelace", ErrPasswordMatchesAccount},
	} {
		t.Run(name, func(t *testing.T) {
			h := newRecoveryHarness(recoveryUser("ada.lovelace@acme.example", "member"))
			_, err := h.uc.ResetPasswordByEmail(context.Background(), "ada.lovelace@acme.example", tc.password)
			assert.ErrorIs(t, err, tc.want)
			assert.Empty(t, h.stored)
		})
	}
}
