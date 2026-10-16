package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const loginRaceUserID = "00000000-0000-0000-0000-000000000040"

func loginRaceFixture(t *testing.T, tokenVersion int32) (*Usecases, *mockRefreshTokenRepo, string) {
	t.Helper()
	hash, err := auth.HashPassword("correct-password")
	require.NoError(t, err)
	users := &mockUserRepo{getByEmailFn: func(context.Context, string) (port.User, error) {
		u := makeUser(loginRaceUserID)
		u.PasswordHash = hash
		u.TokenVersion = tokenVersion
		return u, nil
	}}
	refresh := &mockRefreshTokenRepo{}
	uc := New(Deps{
		Stores:    &port.Stores{Users: users, RefreshTokens: refresh},
		Tokens:    testJWT(t),
		Passwords: auth.NewPasswordHasher(),
	})
	return uc, refresh, hash
}

// The session is stored against the hash the login verified and the generation
// it read before the verify, so the store can tell that the account changed.
func TestLogin_StoresTheSessionAgainstWhatItVerified(t *testing.T) {
	uc, refresh, hash := loginRaceFixture(t, 4)
	var got port.LoginGuard
	refresh.createForLoginFn = func(_ context.Context, _ port.NewRefreshToken, guard port.LoginGuard) (int32, error) {
		got = guard
		return 4, nil
	}

	_, err := uc.Login(context.Background(), "test@example.com", "correct-password")
	require.NoError(t, err)
	assert.Equal(t, port.LoginGuard{PasswordHash: hash, TokenVersion: 4}, got)
}

// The access token carries the generation the store read under its lock, not
// the one read before the password verify.
func TestLogin_AccessTokenCarriesTheGenerationReadUnderTheLock(t *testing.T) {
	uc, refresh, _ := loginRaceFixture(t, 4)
	refresh.createForLoginFn = func(context.Context, port.NewRefreshToken, port.LoginGuard) (int32, error) { return 9, nil }
	jwt := testJWT(t)
	uc.deps.Tokens = jwt

	resp, err := uc.Login(context.Background(), "test@example.com", "correct-password")
	require.NoError(t, err)

	versions := &mockUserRepo{tokenVersionFn: func(context.Context, string) (int32, error) { return 9, nil }}
	_, err = jwt.WithTokenVersions(versions).Authenticate(context.Background(), resp.Token)
	require.NoError(t, err, "the token is bound to generation 9")
	versions.tokenVersionFn = func(context.Context, string) (int32, error) { return 4, nil }
	_, err = jwt.Authenticate(context.Background(), resp.Token)
	require.Error(t, err, "the token is not bound to generation 4")
}

// An account that changed during the password check gets the answer a wrong
// password gets, and no tokens.
func TestLogin_AccountChangedDuringTheCheckIsRefusedLikeAWrongPassword(t *testing.T) {
	uc, refresh, _ := loginRaceFixture(t, 4)
	refresh.createForLoginFn = func(context.Context, port.NewRefreshToken, port.LoginGuard) (int32, error) {
		return 0, port.ErrLoginStale
	}

	resp, err := uc.Login(context.Background(), "test@example.com", "correct-password")
	require.EqualError(t, err, authMsgInvalidCredentials)
	assert.Nil(t, resp)
}
