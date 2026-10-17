package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// Runes in the Unicode categories Zl, Zp and Cf. mail.ParseAddress accepts
// every one of them, so without a check each reaches the stored address.
var formatRunes = map[string]string{
	"line separator U+2028":      "\u2028",
	"paragraph separator U+2029": "\u2029",
	"right-to-left override":     "\u202e",
	"zero-width space":           "\u200b",
	"byte order mark":            "\ufeff",
}

func TestNormalizeAddress_RefusesFormatAndSeparatorRunes(t *testing.T) {
	for name, r := range formatRunes {
		for place, email := range map[string]string{
			"local part": "ad" + r + "a@example.com",
			"domain":     "ada@exam" + r + "ple.com",
			"trailing":   "ada@example.com" + r,
			"leading":    r + "ada@example.com",
		} {
			t.Run(name+"/"+place, func(t *testing.T) {
				_, err := normalizeAddress(email)
				assert.ErrorIs(t, err, ErrInvalidCredentialInput)
				assert.EqualError(t, err, "invalid email address", "the answer every other bad address gets")
				_, err = validateEmail(email)
				assert.ErrorIs(t, err, ErrInvalidCredentialInput)
			})
		}
	}
}

func TestNormalizeAddress_AcceptsPlainAndNonASCIILetters(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"ascii":            {"Ada@Example.com", "ada@example.com"},
		"accented letter":  {"adé@example.com", "adé@example.com"},
		"cjk local part":   {"李雷@example.com", "李雷@example.com"},
		"cyrillic letters": {"ада@example.com", "ада@example.com"},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := normalizeAddress(tc.in)
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestRegister_RefusesFormatAndSeparatorRunesAndCreatesNoUser(t *testing.T) {
	for name, r := range formatRunes {
		t.Run(name, func(t *testing.T) {
			ur := &mockUserRepo{
				getByEmailFn: func(context.Context, string) (port.User, error) {
					t.Fatal("a refused address must not be looked up")
					return port.User{}, nil
				},
				createFn: func(context.Context, string, *string, *string) (port.User, error) {
					t.Fatal("a refused address must not create a user")
					return port.User{}, nil
				},
			}
			uc := New(Deps{Stores: &port.Stores{Users: ur}})

			_, err := uc.Register(context.Background(), "ad"+r+"a@example.com", "a-long-unrelated-phrase")

			assert.ErrorIs(t, err, ErrInvalidCredentialInput)
			assert.EqualError(t, err, "invalid email address")
		})
	}
}

func TestFindOrProvisionSSOUser_RefusesFormatAndSeparatorRunes(t *testing.T) {
	for name, r := range formatRunes {
		for place, email := range map[string]string{
			"inside":   "ad" + r + "a@example.com",
			"trailing": "ada@example.com" + r,
		} {
			t.Run(name+"/"+place, func(t *testing.T) {
				ur := &mockUserRepo{
					getByEmailFn: func(context.Context, string) (port.User, error) {
						t.Fatal("a refused address must not be looked up")
						return port.User{}, nil
					},
					createFn: func(context.Context, string, *string, *string) (port.User, error) {
						t.Fatal("a refused address must not create a user")
						return port.User{}, nil
					},
				}
				ids := newMockIdentityRepo()

				_, _, _, err := New(ssoDepsWith(ur, ids)).FindOrProvisionSSOUser(
					context.Background(), verifiedClaims("sub-format", email), []string{"example.com"}, nil)

				require.ErrorIs(t, err, auth.ErrSSOInvalidEmail)
				assert.Empty(t, ids.links)
			})
		}
	}
}

func TestCreateInvite_RefusesFormatAndSeparatorRunes(t *testing.T) {
	for name, r := range formatRunes {
		for place, email := range map[string]string{
			"inside":   "ad" + r + "a@example.com",
			"trailing": "ada@example.com" + r,
		} {
			t.Run(name+"/"+place, func(t *testing.T) {
				f := newInviteTestFixture(t, auth.RoleManager)

				_, err := f.uc.CreateInvite(callerCtx(), "payments", CreateInviteInput{Role: "member", Email: email})

				assert.ErrorIs(t, err, ErrInvalidInviteInput)
				assert.Empty(t, f.invites.byHash)
			})
		}
	}
}

// Login does not run the address rules. An account stored before they existed
// keeps signing in under the address it has.
func TestLogin_AnAccountWithAFormatRuneStillSignsIn(t *testing.T) {
	const stored = "ada\u200b@example.com"
	hash, err := auth.HashPassword("correct-password")
	require.NoError(t, err)
	var asked string
	users := &mockUserRepo{getByEmailFn: func(_ context.Context, email string) (port.User, error) {
		asked = email
		u := makeUser(loginRaceUserID)
		u.Email = email
		u.PasswordHash = hash
		return u, nil
	}}
	refresh := &mockRefreshTokenRepo{}
	refresh.createForLoginFn = func(context.Context, port.NewRefreshToken, port.LoginGuard) (int32, error) { return 0, nil }
	uc := New(Deps{
		Stores:    &port.Stores{Users: users, RefreshTokens: refresh},
		Tokens:    testJWT(t),
		Passwords: auth.NewPasswordHasher(),
	})

	resp, err := uc.Login(context.Background(), stored, "correct-password")

	require.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
	assert.Equal(t, stored, asked, "the address reaches the lookup unchanged")
}
