package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const lifetimeUserID = "00000000-0000-0000-0000-000000000040"

// lifetimeHarness wires a Refresh use case to an in-memory token store with a
// controllable clock, and records every token the use case persists.
type lifetimeHarness struct {
	uc      *Usecases
	now     time.Time
	stored  port.RefreshToken
	created []port.NewRefreshToken
	revoked int
}

func newLifetimeHarness(t *testing.T, maxAge time.Duration) *lifetimeHarness {
	t.Helper()
	h := &lifetimeHarness{now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	rr := &mockRefreshTokenRepo{
		getByHashFn: func(context.Context, string) (port.RefreshToken, error) { return h.stored, nil },
		revokeFn: func(context.Context, string) (port.RefreshToken, error) {
			h.revoked++
			return h.stored, nil
		},
		createFn: func(_ context.Context, in port.NewRefreshToken) (port.RefreshToken, error) {
			h.created = append(h.created, in)
			return port.RefreshToken{}, nil
		},
	}
	ur := &mockUserRepo{getByIDFn: func(context.Context, string) (port.User, error) {
		return makeUser(lifetimeUserID), nil
	}}
	h.uc = New(Deps{
		Stores:        &port.Stores{RefreshTokens: rr, Users: ur},
		Tokens:        testJWT(t),
		Passwords:     auth.NewPasswordHasher(),
		SessionMaxAge: maxAge,
		Now:           func() time.Time { return h.now },
	})
	return h
}

// token stores a live (unrevoked, unexpired) token whose sign-in began age ago.
func (h *lifetimeHarness) token(familyAge time.Duration) {
	h.stored = port.RefreshToken{
		ID:              "00000000-0000-0000-0000-000000000030",
		UserID:          lifetimeUserID,
		TokenHash:       "hash",
		ExpiresAt:       h.now.Add(24 * time.Hour),
		FamilyID:        "00000000-0000-0000-0000-000000000051",
		FamilyStartedAt: h.now.Add(-familyAge),
	}
}

func TestSessionLifetime_NewSignInStartsAFamilyAtTheClock(t *testing.T) {
	h := newLifetimeHarness(t, 0)

	_, err := h.uc.createSession(context.Background(), lifetimeUserID, "a@example.com")
	require.NoError(t, err)

	require.Len(t, h.created, 1)
	in := h.created[0]
	_, parseErr := uuid.Parse(in.FamilyID)
	require.NoError(t, parseErr, "a new sign-in gets a fresh family id")
	assert.Equal(t, h.now, in.FamilyStartedAt)
	assert.Equal(t, h.now.Add(refreshTokenTTL), in.ExpiresAt)

	_, err = h.uc.createSession(context.Background(), lifetimeUserID, "a@example.com")
	require.NoError(t, err)
	assert.NotEqual(t, in.FamilyID, h.created[1].FamilyID, "two sign-ins never share a family")
}

func TestSessionLifetime_RotationKeepsTheFamilyAndItsStart(t *testing.T) {
	h := newLifetimeHarness(t, 0)
	h.token(10 * 24 * time.Hour)

	_, err := h.uc.Refresh(context.Background(), "raw")
	require.NoError(t, err)

	require.Len(t, h.created, 1)
	assert.Equal(t, h.stored.FamilyID, h.created[0].FamilyID)
	assert.True(t, h.created[0].FamilyStartedAt.Equal(h.stored.FamilyStartedAt),
		"rotation must not move the original sign-in time forward")
}

func TestSessionLifetime_RefreshPastTheAbsoluteLifetimeIsRefused(t *testing.T) {
	h := newLifetimeHarness(t, 0)
	h.token(31 * 24 * time.Hour)

	_, err := h.uc.Refresh(context.Background(), "raw")

	require.EqualError(t, err, "refresh token has expired", "same error an expired token gets")
	assert.Zero(t, h.revoked, "a refused refresh changes nothing")
	assert.Empty(t, h.created)
}

func TestSessionLifetime_BoundaryIsInclusive(t *testing.T) {
	h := newLifetimeHarness(t, 0)

	h.token(DefaultSessionMaxAge - time.Second)
	_, err := h.uc.Refresh(context.Background(), "raw")
	require.NoError(t, err, "one second before the limit still rotates")

	h.created = nil
	h.token(DefaultSessionMaxAge)
	_, err = h.uc.Refresh(context.Background(), "raw")
	require.EqualError(t, err, "refresh token has expired", "the limit itself is over")
}

func TestSessionLifetime_ConfiguredLimitReplacesTheDefault(t *testing.T) {
	h := newLifetimeHarness(t, 48*time.Hour)

	h.token(47 * time.Hour)
	_, err := h.uc.Refresh(context.Background(), "raw")
	require.NoError(t, err)

	h.token(49 * time.Hour)
	_, err = h.uc.Refresh(context.Background(), "raw")
	require.EqualError(t, err, "refresh token has expired")
}

func TestSessionLifetime_RotatedTokenNeverOutlivesTheSession(t *testing.T) {
	h := newLifetimeHarness(t, 0)
	h.token(DefaultSessionMaxAge - 24*time.Hour)

	_, err := h.uc.Refresh(context.Background(), "raw")
	require.NoError(t, err)

	require.Len(t, h.created, 1)
	assert.Equal(t, h.now.Add(24*time.Hour), h.created[0].ExpiresAt,
		"with a day of session left the new token expires in a day, not a week")
}
