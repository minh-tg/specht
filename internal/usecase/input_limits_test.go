package usecase

import (
	"context"
	"strings"
	"testing"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const limitsPassword = "correct-horse-battery"

// emailOfBytes returns a well-formed address that is exactly n bytes long.
func emailOfBytes(n int) string {
	const tail = "@example.com"
	return strings.Repeat("a", n-len(tail)) + tail
}

// nameOfRunes returns a display name of n characters that each take two bytes,
// so a byte count would reject it long before a character count does.
func nameOfRunes(n int) string { return strings.Repeat("é", n) }

func TestInputLimits_EmailIsCappedAt254Bytes(t *testing.T) {
	_, err := validateCredentials(emailOfBytes(254), limitsPassword, "")
	require.NoError(t, err, "254 bytes is the longest address allowed")

	_, err = validateCredentials(emailOfBytes(255), limitsPassword, "")
	require.ErrorIs(t, err, ErrInvalidCredentialInput)
	assert.Contains(t, err.Error(), "254")

	_, err = validateCredentials(emailOfBytes(1<<20), limitsPassword, "")
	assert.ErrorIs(t, err, ErrInvalidCredentialInput, "a megabyte of address never reaches the parser")
}

func TestInputLimits_DisplayNameIsCappedAt100Characters(t *testing.T) {
	_, err := validateCredentials("ok@example.com", limitsPassword, nameOfRunes(100))
	require.NoError(t, err, "100 characters is allowed even when they take 200 bytes")

	_, err = validateCredentials("ok@example.com", limitsPassword, nameOfRunes(101))
	require.ErrorIs(t, err, ErrInvalidCredentialInput)
	assert.Contains(t, err.Error(), "100")
}

func TestInputLimits_RegisterRefusesALongEmail(t *testing.T) {
	uc := New(Deps{Stores: &port.Stores{Users: &mockUserRepo{}}, Passwords: auth.NewPasswordHasher()})

	_, err := uc.Register(context.Background(), emailOfBytes(255), limitsPassword)

	assert.ErrorIs(t, err, ErrInvalidCredentialInput)
}

func TestInputLimits_SetupRefusesALongEmailOrName(t *testing.T) {
	for name, mutate := range map[string]func(*SetupInput){
		"email": func(in *SetupInput) { in.Email = emailOfBytes(255) },
		"name":  func(in *SetupInput) { in.DisplayName = nameOfRunes(101) },
	} {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t, 0)
			in := validSetup()
			mutate(&in)

			_, err := f.uc.Setup(context.Background(), in)

			assert.ErrorIs(t, err, ErrInvalidCredentialInput)
			assert.Empty(t, f.created)
		})
	}
}

func TestInputLimits_AcceptInviteRefusesALongEmailOrName(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)
	link, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member"})
	require.NoError(t, err)
	token := strings.TrimPrefix(link.Link, "/invite/")

	for name, in := range map[string]AcceptInviteInput{
		"email": {Email: emailOfBytes(255), Password: limitsPassword},
		"name":  {Email: "new@example.com", Password: limitsPassword, DisplayName: nameOfRunes(101)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := f.uc.AcceptInvite(context.Background(), token, in)
			assert.ErrorIs(t, err, ErrInvalidCredentialInput)
		})
	}
}

func TestInputLimits_CreateInviteRefusesALongEmail(t *testing.T) {
	f := newInviteTestFixture(t, auth.RoleManager)

	_, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member", Email: emailOfBytes(255)})
	assert.ErrorIs(t, err, ErrInvalidInviteInput)

	_, err = f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member", Email: emailOfBytes(254)})
	assert.NoError(t, err)
}

func TestInputLimits_AddMemberRefusesALongEmail(t *testing.T) {
	_, err := memberEmail(emailOfBytes(255))
	assert.ErrorIs(t, err, ErrInvalidMemberEmail)

	_, err = memberEmail(emailOfBytes(254))
	assert.NoError(t, err)
}

func TestInputLimits_ProfileNameIsCappedAfterTrimming(t *testing.T) {
	ur := &mockUserRepo{updateDisplayNameFn: func(_ context.Context, _ string, name *string) (port.User, error) {
		u := makeUser("00000000-0000-0000-0000-000000000040")
		u.DisplayName = name
		return u, nil
	}}
	uc := New(Deps{Stores: &port.Stores{Users: ur}})
	update := func(name string) error {
		_, err := uc.UpdateProfile(context.Background(), "00000000-0000-0000-0000-000000000040", &name)
		return err
	}

	assert.NoError(t, update(nameOfRunes(100)))
	assert.NoError(t, update("  "+nameOfRunes(100)+"  "), "spaces around the name do not count")
	assert.ErrorIs(t, update(nameOfRunes(101)), ErrInvalidProfileInput)
	assert.ErrorIs(t, update(strings.Repeat("x", 1<<20)), ErrInvalidProfileInput)
}
