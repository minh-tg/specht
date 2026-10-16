//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
)

const changeSessionOldPassword = "an-Old-password-1234"

// beforeSessionStore runs hook once, right before the caller's session of a
// password change is stored. Whichever store call the usecase uses for that
// session (Create or CreateForLogin) goes through here, so the hook sits in the
// window between the change committing and the session being written.
type beforeSessionStore struct {
	port.RefreshTokenStore
	hook func()
}

func (s *beforeSessionStore) fire() {
	if s.hook != nil {
		hook := s.hook
		s.hook = nil
		hook()
	}
}

func (s *beforeSessionStore) Create(ctx context.Context, in port.NewRefreshToken) (port.RefreshToken, error) {
	s.fire()
	return s.RefreshTokenStore.Create(ctx, in)
}

func (s *beforeSessionStore) CreateForLogin(ctx context.Context, in port.NewRefreshToken, guard port.LoginGuard) (int32, error) {
	s.fire()
	return s.RefreshTokenStore.CreateForLogin(ctx, in, guard)
}

// An SSO link commits after ChangePassword wrote the new password and before
// the caller's own session is stored. The link clears the password, starts a new
// token generation and revokes the refresh tokens that exist at that moment, so
// a session stored afterwards under the old generation would outlive it. The
// change must report the account change and leave no live refresh token.
func TestChangePasswordLeavesNoSessionWhenAnSSOLinkCommitsBeforeTheCallersSession(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)

	hasher := auth.NewPasswordHasher()
	hash, err := hasher.Hash(changeSessionOldPassword)
	require.NoError(t, err)
	created, err := stores.Users.Create(ctx, "change-then-link@test.com", nil, &hash)
	require.NoError(t, err)

	wrapped := *stores
	hooked := &beforeSessionStore{RefreshTokenStore: stores.RefreshTokens}
	wrapped.RefreshTokens = hooked
	hooked.hook = func() {
		_, _, err := stores.Identities.LinkRevokingKeys(ctx, created.ID, "https://idp.example", "change-then-link-sub", true)
		require.NoError(t, err)
	}
	jwt, err := auth.NewJWTAuthenticator("change-session-secret-change-session-secret")
	require.NoError(t, err)
	uc := usecase.New(usecase.Deps{Stores: &wrapped, Tokens: jwt, Passwords: hasher})

	resp, err := uc.ChangePassword(ctx, created.ID, changeSessionOldPassword, "a-New-password-5678")
	assert.Nil(t, resp, "the caller gets no session from a generation the link ended")
	assert.Error(t, err)
	assert.Nil(t, hooked.hook, "the link ran between the change and the caller's session")

	assert.Zero(t, liveRefreshTokens(t, repos, created.ID), "the caller's session outlives the SSO link")
}
