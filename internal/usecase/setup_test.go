package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

type setupFixture struct {
	uc      *Usecases
	users   *mockUserRepo
	token   *SetupToken
	created []port.User
}

func newSetupFixture(t *testing.T, existingAdmins int64) *setupFixture {
	t.Helper()
	f := &setupFixture{users: &mockUserRepo{}}
	var err error
	f.token, err = NewSetupToken("s3cret-token-0123456789")
	require.NoError(t, err)

	f.users.countAdminsFn = func(context.Context) (int64, error) { return existingAdmins + int64(len(f.created)), nil }
	f.users.createFirstAdminFn = func(_ context.Context, email string, name *string, hash string) (port.User, error) {
		if existingAdmins+int64(len(f.created)) > 0 {
			return port.User{}, port.ErrSetupClosed
		}
		u := makeUser("00000000-0000-0000-0000-0000000000f1")
		u.Email, u.Role, u.PasswordHash = email, auth.RoleAdmin, hash
		if name != nil {
			u.DisplayName = name
		}
		f.created = append(f.created, u)
		return u, nil
	}
	refresh := &mockRefreshTokenRepo{createFn: func(context.Context, port.NewRefreshToken) (port.RefreshToken, error) {
		return makeRefreshToken(false), nil
	}}
	f.uc = New(Deps{
		Stores:     &port.Stores{Users: f.users, RefreshTokens: refresh},
		Tokens:     testJWT(t),
		Passwords:  auth.NewPasswordHasher(),
		SetupToken: f.token,
	})
	return f
}

func validSetup() SetupInput {
	return SetupInput{Token: "s3cret-token-0123456789", Email: "Root@Example.com", Password: "correct-horse-battery", DisplayName: " Root "}
}

func TestSetup_CreatesTheFirstAdminAndSignsThemIn(t *testing.T) {
	f := newSetupFixture(t, 0)

	resp, err := f.uc.Setup(context.Background(), validSetup())

	require.NoError(t, err)
	require.Len(t, f.created, 1)
	assert.Equal(t, "root@example.com", f.created[0].Email, "email is normalised like registration")
	assert.Equal(t, "Root", *f.created[0].DisplayName)
	assert.NotEqual(t, "correct-horse-battery", f.created[0].PasswordHash, "the password is stored hashed")
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.RefreshToken)

	id, err := testJWT(t).Authenticate(context.Background(), resp.Token)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleAdmin, id.Role, "the first account is a global admin")
}

func TestSetup_WorksOnlyOnce(t *testing.T) {
	f := newSetupFixture(t, 0)
	_, err := f.uc.Setup(context.Background(), validSetup())
	require.NoError(t, err)

	_, err = f.uc.Setup(context.Background(), validSetup())

	assert.ErrorIs(t, err, ErrSetupClosed)
	assert.Len(t, f.created, 1)
	assert.Empty(t, f.token.Value(), "the token is forgotten once it has done its job")
}

func TestSetup_ClosedWhenAnAdminAlreadyExists(t *testing.T) {
	f := newSetupFixture(t, 1)

	required, err := f.uc.SetupRequired(context.Background())
	require.NoError(t, err)
	assert.False(t, required)

	_, err = f.uc.Setup(context.Background(), validSetup())
	assert.ErrorIs(t, err, ErrSetupClosed)
	assert.Empty(t, f.created)
}

func TestSetup_StaysOpenWhileOnlyNonAdminsExist(t *testing.T) {
	f := newSetupFixture(t, 0)
	// A stranger registered before the operator: accounts exist, none is an admin.
	f.users.countFn = func(context.Context) (int64, error) { return 3, nil }

	required, err := f.uc.SetupRequired(context.Background())
	require.NoError(t, err)
	assert.True(t, required, "registered non-admin accounts must not close setup")

	_, err = f.uc.Setup(context.Background(), validSetup())
	require.NoError(t, err)
	require.Len(t, f.created, 1)
	assert.Equal(t, auth.RoleAdmin, f.created[0].Role)
}

func TestSetup_ReportsAnEmailThatIsAlreadyRegistered(t *testing.T) {
	f := newSetupFixture(t, 0)
	f.users.createFirstAdminFn = func(context.Context, string, *string, string) (port.User, error) {
		return port.User{}, port.ErrEmailTaken
	}

	_, err := f.uc.Setup(context.Background(), validSetup())

	assert.ErrorIs(t, err, ErrSetupEmailTaken)
	assert.Equal(t, "s3cret-token-0123456789", f.token.Value(), "a taken email does not burn the token")
}

func TestSetup_ClosedWhenTheServerOffersNoToken(t *testing.T) {
	users := &mockUserRepo{countAdminsFn: func(context.Context) (int64, error) { return 0, nil }}
	uc := New(Deps{Stores: &port.Stores{Users: users}})

	required, err := uc.SetupRequired(context.Background())
	require.NoError(t, err)
	assert.False(t, required, "without a token nobody can complete setup, so the UI must not offer it")

	_, err = uc.Setup(context.Background(), validSetup())
	assert.ErrorIs(t, err, ErrSetupClosed)
}

func TestSetup_RejectsAMissingOrWrongToken(t *testing.T) {
	for name, token := range map[string]string{
		"missing":          "",
		"wrong":            "guess",
		"prefix of actual": "s3cret-token-0123",
		"actual plus more": "s3cret-token-0123456789-and-more",
	} {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t, 0)
			in := validSetup()
			in.Token = token

			_, err := f.uc.Setup(context.Background(), in)

			assert.ErrorIs(t, err, ErrInvalidSetupToken)
			assert.Empty(t, f.created)
			assert.Equal(t, "s3cret-token-0123456789", f.token.Value(), "a failed attempt leaves the token usable")
		})
	}
}

func TestSetup_ValidatesTheAccountBeforeCreatingIt(t *testing.T) {
	for name, in := range map[string]SetupInput{
		"no email":      {Token: "s3cret-token-0123456789", Password: "correct-horse-battery"},
		"bad email":     {Token: "s3cret-token-0123456789", Email: "not-an-email", Password: "correct-horse-battery"},
		"short":         {Token: "s3cret-token-0123456789", Email: "a@example.com", Password: "short"},
		"empty":         {Token: "s3cret-token-0123456789"},
		"blank display": {Token: "s3cret-token-0123456789", Email: "a@example.com", Password: "short", DisplayName: "  "},
	} {
		t.Run(name, func(t *testing.T) {
			f := newSetupFixture(t, 0)

			_, err := f.uc.Setup(context.Background(), in)

			assert.ErrorIs(t, err, ErrInvalidCredentialInput)
			assert.Empty(t, f.created)
			assert.Equal(t, "s3cret-token-0123456789", f.token.Value(), "a typo in the form does not burn the token")
		})
	}
}

func TestSetup_LosingTheRaceReportsClosed(t *testing.T) {
	f := newSetupFixture(t, 0)
	// Another request creates the admin between the check and the insert.
	f.users.createFirstAdminFn = func(context.Context, string, *string, string) (port.User, error) {
		return port.User{}, port.ErrSetupClosed
	}

	_, err := f.uc.Setup(context.Background(), validSetup())

	assert.ErrorIs(t, err, ErrSetupClosed)
}

func TestSetupToken(t *testing.T) {
	t.Run("generated tokens are long and differ", func(t *testing.T) {
		a, err := NewSetupToken("")
		require.NoError(t, err)
		b, err := NewSetupToken("")
		require.NoError(t, err)
		assert.GreaterOrEqual(t, len(a.Value()), 32)
		assert.NotEqual(t, a.Value(), b.Value())
	})
	t.Run("a cleared token verifies nothing, not even the empty string", func(t *testing.T) {
		tok, err := NewSetupToken("abcdefghijklmnop")
		require.NoError(t, err)
		require.True(t, tok.Verify("abcdefghijklmnop"))
		tok.Clear()
		assert.False(t, tok.Verify("abcdefghijklmnop"))
		assert.False(t, tok.Verify(""))
	})
	t.Run("an operator-chosen token must be long enough to resist guessing", func(t *testing.T) {
		_, err := NewSetupToken("short")
		assert.Error(t, err)
	})
}

// A request that read "setup required" just before another request finished
// setup must answer closed, not "wrong token": the winner clears the token, so
// the loser's valid token no longer verifies.
func TestSetup_ALoserOfTheRaceAnswersClosedNotWrongToken(t *testing.T) {
	f := newSetupFixture(t, 0)
	calls := 0
	f.users.countAdminsFn = func(context.Context) (int64, error) {
		calls++
		if calls == 1 {
			f.token.Clear()
			return 0, nil
		}
		return 1, nil
	}

	_, err := f.uc.Setup(context.Background(), validSetup())

	assert.ErrorIs(t, err, ErrSetupClosed)
	assert.Empty(t, f.created)
}

func TestSetup_AWrongTokenWhileSetupIsOpenIsStillRefused(t *testing.T) {
	f := newSetupFixture(t, 0)
	in := validSetup()
	in.Token = "not-the-token-0000000000"

	_, err := f.uc.Setup(context.Background(), in)

	assert.ErrorIs(t, err, ErrInvalidSetupToken)
}
