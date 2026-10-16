package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// kelvinKate spells "kate" with U+212A (Kelvin sign), which Go lower-cases to
// "k" and PostgreSQL's lower() may as well. It must reach no account that
// "kate" reaches, and no new account may be created under it.
const kelvinKate = "Kate@corp.example"

func TestValidateCredentials_RefusesAnAddressWithAnAmbiguousCase(t *testing.T) {
	_, err := validateCredentials(kelvinKate, "a long enough password", "")
	assert.ErrorIs(t, err, ErrInvalidCredentialInput)
	assert.EqualError(t, err, "invalid email address", "the answer an unparsable address gets")

	got, err := validateCredentials("Kate@Corp.Example", "a long enough password", "")
	require.NoError(t, err)
	assert.Equal(t, "kate@corp.example", got)
}

func TestCreateInvite_RefusesAnAddressWithAnAmbiguousCase(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)

	_, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member", Email: kelvinKate})

	assert.ErrorIs(t, err, ErrInvalidInviteInput)
	assert.Empty(t, f.invites.byHash)
}

func TestMemberEmail_RefusesAnAddressWithAnAmbiguousCase(t *testing.T) {
	_, err := memberEmail(kelvinKate)
	assert.ErrorIs(t, err, ErrInvalidMemberEmail)
}

func TestLogin_AnAmbiguousAddressReachesNoAccount(t *testing.T) {
	var asked []string
	users := &mockUserRepo{getByEmailFn: func(_ context.Context, email string) (port.User, error) {
		asked = append(asked, email)
		if email == "kate@corp.example" {
			return port.User{ID: "u1", Email: email, PasswordHash: "hash"}, nil
		}
		return port.User{}, port.ErrNotFound
	}}
	uc := New(Deps{Stores: &port.Stores{Users: users}, Passwords: auth.NewPasswordHasher()})

	_, err := uc.Login(context.Background(), kelvinKate, "whatever password")

	require.Error(t, err)
	assert.NotContains(t, asked, "kate@corp.example", "the Kelvin spelling is not folded into the ASCII account")
}

func TestSSO_AnAmbiguousVerifiedEmailLinksNoAccount(t *testing.T) {
	ids := newMockIdentityRepo()
	ur := &mockUserRepo{}
	ur.getByEmailFn = func(context.Context, string) (port.User, error) {
		t.Fatal("an address with an ambiguous case must not be looked up")
		return port.User{}, nil
	}

	_, _, _, err := New(ssoDepsWith(ur, ids)).FindOrProvisionSSOUser(
		context.Background(), verifiedClaims("sub-kelvin", kelvinKate), []string{"corp.example"}, nil)

	assert.ErrorIs(t, err, auth.ErrSSONotProvisioned)
	assert.Empty(t, ids.links, "the provider vouching for the address does not make it linkable")
}

func TestRecovery_AnAmbiguousAddressIsRefused(t *testing.T) {
	users := &mockUserRepo{getByEmailFn: func(context.Context, string) (port.User, error) {
		t.Fatal("an address with an ambiguous case must not be looked up")
		return port.User{}, nil
	}}
	uc := New(Deps{Stores: &port.Stores{Users: users}})

	_, err := uc.GrantAdminByEmail(context.Background(), kelvinKate)
	assert.ErrorIs(t, err, ErrInvalidCredentialInput)
	assert.EqualError(t, err, "invalid email address")
	_, err = uc.ResetPasswordByEmail(context.Background(), kelvinKate, "a long enough password")
	assert.ErrorIs(t, err, ErrInvalidCredentialInput)
	assert.EqualError(t, err, "invalid email address")
}

// Registration, invites and setup reach normalizeAddress through validateEmail
// or validateCredentials. A control character is refused before the address is
// parsed, so U+0085 (NEL), which mail.ParseAddress accepts, never reaches an
// account.
func TestNormalizeAddress_RefusesAControlCharacter(t *testing.T) {
	for name, email := range map[string]string{
		"NEL in the local part": "ada\u0085@example.com",
		"NEL after the domain":  "ada@example.com\u0085",
		"NUL":                   "ada\x00@example.com",
		"DEL":                   "ada\x7f@example.com",
		"tab":                   "ada\t@example.com",
		"newline":               "ada@example.com\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := normalizeAddress(email)
			assert.ErrorIs(t, err, ErrInvalidCredentialInput)
			assert.EqualError(t, err, "invalid email address")
			_, err = validateCredentials(email, "a long enough password", "")
			assert.ErrorIs(t, err, ErrInvalidCredentialInput)
		})
	}

	got, err := normalizeAddress("Ada@Example.com")
	require.NoError(t, err)
	assert.Equal(t, "ada@example.com", got)
}
