package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	adminUserID  = "00000000-0000-0000-0000-0000000000a1"
	targetUserID = "00000000-0000-0000-0000-0000000000a2"
)

func userAdminUsecase(users *mockUserRepo, refresh *mockRefreshTokenRepo) *Usecases {
	return New(Deps{Stores: &port.Stores{Users: users, RefreshTokens: refresh}})
}

func TestUserAdminNeedsAGlobalAdmin(t *testing.T) {
	uc := userAdminUsecase(&mockUserRepo{}, &mockRefreshTokenRepo{})
	for name, ctx := range map[string]context.Context{
		"anonymous":      context.Background(),
		"plain member":   sessionCtx(adminUserID, auth.RoleMember),
		"project admin":  sessionCtx(adminUserID, auth.RoleManager),
		"admin API key":  apiKeyCtx("key-1", "p1"),
		"viewer session": sessionCtx(adminUserID, auth.RoleViewer),
	} {
		_, err := uc.ChangeUserRole(ctx, targetUserID, "admin")
		assert.ErrorIs(t, err, ErrProjectAccessDenied, name)
		_, _, err = uc.DeactivateUser(ctx, targetUserID)
		assert.ErrorIs(t, err, ErrProjectAccessDenied, name)
		_, err = uc.ReactivateUser(ctx, targetUserID)
		assert.ErrorIs(t, err, ErrProjectAccessDenied, name)
	}
}

func TestChangeUserRole(t *testing.T) {
	var changedTo string
	users := &mockUserRepo{
		getByIDFn: func(context.Context, string) (port.User, error) {
			return port.User{ID: targetUserID, Email: "t@example.com", Role: auth.RoleMember, CreatedAt: time.Now()}, nil
		},
		changeRoleFn: func(_ context.Context, id, role string) (port.User, error) {
			changedTo = role
			return port.User{ID: id, Email: "t@example.com", Role: role, CreatedAt: time.Now()}, nil
		},
	}
	uc := userAdminUsecase(users, &mockRefreshTokenRepo{})
	ctx := sessionCtx(adminUserID, auth.RoleAdmin)

	profile, err := uc.ChangeUserRole(ctx, targetUserID, auth.RoleAdmin)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleAdmin, changedTo)
	assert.Equal(t, auth.RoleAdmin, profile.Role)

	changedTo = ""
	_, err = uc.ChangeUserRole(ctx, targetUserID, auth.RoleMember)
	require.NoError(t, err)
	assert.Empty(t, changedTo, "an unchanged role must not start a new token generation")

	_, err = uc.ChangeUserRole(ctx, targetUserID, "superuser")
	require.ErrorIs(t, err, ErrInvalidGlobalRole)
	_, err = uc.ChangeUserRole(ctx, "not-a-uuid", auth.RoleAdmin)
	require.ErrorIs(t, err, ErrInvalidID)
}

func TestChangeUserRoleSurfacesTheLastAdminGuard(t *testing.T) {
	users := &mockUserRepo{
		getByIDFn: func(context.Context, string) (port.User, error) {
			return port.User{ID: targetUserID, Role: auth.RoleAdmin}, nil
		},
		changeRoleFn: func(context.Context, string, string) (port.User, error) {
			return port.User{}, port.ErrLastGlobalAdmin
		},
	}
	_, err := userAdminUsecase(users, &mockRefreshTokenRepo{}).ChangeUserRole(sessionCtx(adminUserID, auth.RoleAdmin), targetUserID, auth.RoleMember)
	require.ErrorIs(t, err, ErrLastGlobalAdmin)
}

func TestDeactivateUser(t *testing.T) {
	disabledAt := time.Now()
	var revoked string
	keys := []port.RevokedAPIKey{
		{ID: "k1", ProjectSlug: "my-app", Name: "ci"},
		{ID: "k2", ProjectSlug: "other", Name: "deploy"},
	}
	users := &mockUserRepo{
		getByIDFn: func(_ context.Context, id string) (port.User, error) {
			return port.User{ID: id, Email: "t@example.com", Role: auth.RoleMember}, nil
		},
		deactivateFn: func(_ context.Context, id string) (port.User, []port.RevokedAPIKey, error) {
			return port.User{ID: id, Email: "t@example.com", Role: auth.RoleMember, DisabledAt: &disabledAt, CreatedAt: time.Now()}, keys, nil
		},
	}
	refresh := &mockRefreshTokenRepo{revokeAllFn: func(_ context.Context, id string) error { revoked = id; return nil }}
	uc := userAdminUsecase(users, refresh)

	profile, revokedKeys, err := uc.DeactivateUser(sessionCtx(adminUserID, auth.RoleAdmin), targetUserID)

	require.NoError(t, err)
	assert.True(t, profile.Disabled)
	require.NotNil(t, profile.DisabledAt)
	assert.Equal(t, targetUserID, revoked, "the account's refresh tokens are revoked")
	assert.Equal(t, keys, revokedKeys, "the caller learns which keys went with the account, to write one audit line each")
}

func TestDeactivateUserRefusesYourself(t *testing.T) {
	uc := userAdminUsecase(&mockUserRepo{}, &mockRefreshTokenRepo{})
	_, _, err := uc.DeactivateUser(sessionCtx(adminUserID, auth.RoleAdmin), adminUserID)
	require.ErrorIs(t, err, ErrCannotDeactivateSelf)
}

func TestDeactivateUserSurfacesTheLastAdminGuard(t *testing.T) {
	users := &mockUserRepo{getByIDFn: func(_ context.Context, id string) (port.User, error) {
		return port.User{ID: id, Email: "t@example.com", Role: auth.RoleAdmin}, nil
	}, deactivateFn: func(context.Context, string) (port.User, []port.RevokedAPIKey, error) {
		return port.User{}, nil, port.ErrLastGlobalAdmin
	}}
	_, _, err := userAdminUsecase(users, &mockRefreshTokenRepo{}).DeactivateUser(sessionCtx(adminUserID, auth.RoleAdmin), targetUserID)
	require.ErrorIs(t, err, ErrLastGlobalAdmin)
}

func TestReactivateUser(t *testing.T) {
	users := &mockUserRepo{setDisabledFn: func(_ context.Context, id string, disabled bool) (port.User, error) {
		require.False(t, disabled)
		return port.User{ID: id, Role: auth.RoleMember, CreatedAt: time.Now()}, nil
	}}
	profile, err := userAdminUsecase(users, &mockRefreshTokenRepo{}).ReactivateUser(sessionCtx(adminUserID, auth.RoleAdmin), targetUserID)
	require.NoError(t, err)
	assert.False(t, profile.Disabled)
	assert.Nil(t, profile.DisabledAt)
}

// A deactivated account must not obtain a session by any route.
func TestDeactivatedAccountCannotSignIn(t *testing.T) {
	hash, err := auth.HashPassword("correct-password")
	require.NoError(t, err)
	disabledAt := time.Now()
	disabled := func() port.User {
		u := makeUser(targetUserID)
		u.PasswordHash = hash
		u.DisabledAt = &disabledAt
		return u
	}

	t.Run("login", func(t *testing.T) {
		users := &mockUserRepo{getByEmailFn: func(context.Context, string) (port.User, error) { return disabled(), nil }}
		uc := New(Deps{
			Stores:    &port.Stores{Users: users},
			Tokens:    testJWT(t),
			Passwords: auth.NewPasswordHasher(),
		})
		_, err := uc.Login(context.Background(), "test@example.com", "correct-password")
		require.EqualError(t, err, authMsgInvalidCredentials, "the right password gets the same answer as a wrong one")
	})

	t.Run("refresh", func(t *testing.T) {
		users := &mockUserRepo{getByIDFn: func(context.Context, string) (port.User, error) { return disabled(), nil }}
		refresh := &mockRefreshTokenRepo{
			getByHashFn: func(context.Context, string) (port.RefreshToken, error) { return makeRefreshToken(false), nil },
			revokeFn:    func(context.Context, string) (port.RefreshToken, error) { return port.RefreshToken{}, nil },
		}
		uc := New(Deps{Stores: &port.Stores{Users: users, RefreshTokens: refresh}, Tokens: testJWT(t)})
		_, err := uc.Refresh(context.Background(), "some-refresh-token")
		require.Error(t, err)
	})

	t.Run("sso exchange", func(t *testing.T) {
		users := &mockUserRepo{getByIDFn: func(context.Context, string) (port.User, error) { return disabled(), nil }}
		codes := newMemorySSOCodeStore()
		require.NoError(t, codes.Create(context.Background(), codeHashOf("code"), targetUserID, time.Now().Add(time.Minute)))
		uc := New(Deps{Stores: &port.Stores{Users: users, SSOCodes: codes}, Tokens: testJWT(t)})
		_, err := uc.ExchangeSSOCode(context.Background(), "code")
		require.ErrorIs(t, err, auth.ErrInvalidCredential)
	})
}

func codeHashOf(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

func TestTheSystemAccountCannotBeChanged(t *testing.T) {
	changed := false
	users := &mockUserRepo{
		getByIDFn: func(_ context.Context, id string) (port.User, error) {
			return port.User{ID: id, Email: "System@Specht.Local", Role: auth.RoleMember}, nil
		},
		changeRoleFn: func(context.Context, string, string) (port.User, error) {
			changed = true
			return port.User{}, nil
		},
		deactivateFn: func(context.Context, string) (port.User, []port.RevokedAPIKey, error) {
			changed = true
			return port.User{}, nil, nil
		},
	}
	uc := userAdminUsecase(users, &mockRefreshTokenRepo{})
	ctx := sessionCtx(adminUserID, auth.RoleAdmin)

	_, err := uc.ChangeUserRole(ctx, targetUserID, auth.RoleAdmin)
	require.ErrorIs(t, err, ErrSystemAccount)
	_, _, err = uc.DeactivateUser(ctx, targetUserID)
	require.ErrorIs(t, err, ErrSystemAccount)
	assert.False(t, changed, "nothing is written for the system account")
}
