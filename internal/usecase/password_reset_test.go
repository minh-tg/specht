package usecase

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const resetTestUser = "00000000-0000-4000-8000-0000000000a1"

type fakeResetStore struct {
	created []port.NewPasswordReset
	// redeemed holds the hash of the password the last Redeem was given.
	redeemedHash string
	redeemErr    error
	redeemUser   string
}

func (f *fakeResetStore) Create(_ context.Context, in port.NewPasswordReset) error {
	f.created = append(f.created, in)
	return nil
}

func (f *fakeResetStore) Redeem(_ context.Context, _, passwordHash string) (string, error) {
	f.redeemedHash = passwordHash
	return f.redeemUser, f.redeemErr
}

func resetHarness(user port.User) (*Usecases, *fakeResetStore) {
	store := &fakeResetStore{redeemUser: resetTestUser}
	users := &mockUserRepo{getByIDFn: func(context.Context, string) (port.User, error) { return user, nil }}
	uc := New(Deps{
		Stores:    &port.Stores{Users: users, PasswordReset: store},
		Passwords: auth.NewPasswordHasher(),
	})
	return uc, store
}

func localUser() port.User {
	return port.User{ID: resetTestUser, Email: "ada@acme.example", PasswordHash: "x", Role: auth.RoleMember}
}

func TestCreatePasswordResetLink_StoresOnlyTheHashAndReturnsAWorkingLink(t *testing.T) {
	uc, store := resetHarness(localUser())

	out, err := uc.CreatePasswordResetLink(adminCtx(), resetTestUser)
	require.NoError(t, err)
	require.True(t, strings.HasPrefix(out.Link, "/reset/"))
	token := strings.TrimPrefix(out.Link, "/reset/")
	require.Len(t, store.created, 1)
	got := store.created[0]
	assert.Equal(t, hashInviteToken(token), got.TokenHash, "the stored value is the token's hash")
	assert.NotContains(t, got.TokenHash, token)
	assert.Equal(t, resetTestUser, got.UserID)
	assert.Equal(t, "00000000-0000-0000-0000-000000000040", got.CreatedBy)
	assert.WithinDuration(t, time.Now().Add(resetLinkTTL), got.ExpiresAt, time.Minute)
	assert.WithinDuration(t, got.ExpiresAt, mustParseTime(t, out.ExpiresAt), time.Second)
}

func ptrTime(t time.Time) *time.Time { return &t }

func mustParseTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, s)
	require.NoError(t, err)
	return v
}

func TestCreatePasswordResetLink_OnlyAnInstanceAdminWithASession(t *testing.T) {
	uc, store := resetHarness(localUser())
	for name, ctx := range map[string]context.Context{
		"member":    sessionCtx("00000000-0000-4000-8000-000000000001", auth.RoleMember),
		"api key":   apiKeyCtx("key-1", findingFixtureProjectID),
		"anonymous": context.Background(),
	} {
		_, err := uc.CreatePasswordResetLink(ctx, resetTestUser)
		assert.ErrorIs(t, err, ErrProjectAccessDenied, name)
	}
	assert.Empty(t, store.created)
}

func TestCreatePasswordResetLink_RefusesAccountsAResetCannotHelp(t *testing.T) {
	for name, tc := range map[string]struct {
		user port.User
		want error
	}{
		"system account": {port.User{ID: resetTestUser, Email: SystemAccountEmail, PasswordHash: "x"}, ErrSystemAccount},
		"sso only":       {port.User{ID: resetTestUser, Email: "sso@acme.example"}, ErrNoLocalPassword},
		"deactivated": {
			port.User{ID: resetTestUser, Email: "gone@acme.example", PasswordHash: "x", DisabledAt: ptrTime(time.Now())},
			ErrAccountDeactivated,
		},
	} {
		uc, store := resetHarness(tc.user)
		_, err := uc.CreatePasswordResetLink(adminCtx(), resetTestUser)
		assert.ErrorIs(t, err, tc.want, name)
		assert.Empty(t, store.created, name)
	}
}

func TestCreatePasswordResetLink_UnknownAccountAndBadID(t *testing.T) {
	store := &fakeResetStore{}
	users := &mockUserRepo{getByIDFn: func(context.Context, string) (port.User, error) {
		return port.User{}, port.ErrNotFound
	}}
	uc := New(Deps{Stores: &port.Stores{Users: users, PasswordReset: store}})

	_, err := uc.CreatePasswordResetLink(adminCtx(), resetTestUser)
	assert.ErrorIs(t, err, ErrAccountNotFound)
	_, err = uc.CreatePasswordResetLink(adminCtx(), "not-a-uuid")
	assert.ErrorIs(t, err, ErrInvalidID)
}

func TestRedeemPasswordReset_SetsAHashedPasswordFromTheToken(t *testing.T) {
	uc, store := resetHarness(localUser())

	require.NoError(t, uc.RedeemPasswordReset(context.Background(), "tok-123", "a long enough password"))
	assert.NotEmpty(t, store.redeemedHash)
	assert.NotContains(t, store.redeemedHash, "a long enough password")
}

func TestRedeemPasswordReset_DeadLinksAllAnswerTheSame(t *testing.T) {
	uc, store := resetHarness(localUser())
	store.redeemErr = port.ErrNotFound

	err := uc.RedeemPasswordReset(context.Background(), "tok-123", "a long enough password")
	assert.ErrorIs(t, err, ErrResetLinkInvalid)

	for _, token := range []string{"", strings.Repeat("a", maxInviteTokenLength+1)} {
		store.redeemedHash = ""
		err = uc.RedeemPasswordReset(context.Background(), token, "a long enough password")
		assert.ErrorIs(t, err, ErrResetLinkInvalid, "token of length %d", len(token))
		assert.Empty(t, store.redeemedHash, "the store is not asked")
	}
}

func TestRedeemPasswordReset_ChecksThePasswordBeforeSpendingTheLink(t *testing.T) {
	uc, store := resetHarness(localUser())

	err := uc.RedeemPasswordReset(context.Background(), "tok-123", "short")
	assert.ErrorIs(t, err, ErrInvalidCredentialInput)
	assert.Empty(t, store.redeemedHash, "a refused password must leave the link unused")
}
