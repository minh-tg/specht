package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memRefreshStore is an in-memory refresh token table with the semantics the
// use case relies on: Revoke is a compare-and-swap that matches only an
// unrevoked row, and revocation stamps the injected clock.
type memRefreshStore struct {
	port.RefreshTokenStore
	mu   sync.Mutex
	now  func() time.Time
	rows []*port.RefreshToken
	// rotateMu makes Rotate atomic against another Rotate.
	rotateMu sync.Mutex
	guard    func(userID string, tokenVersion int32) error
}

func (m *memRefreshStore) Create(_ context.Context, in port.NewRefreshToken) (port.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row := &port.RefreshToken{
		ID: "row-" + in.TokenHash[:8], UserID: in.UserID, TokenHash: in.TokenHash, ExpiresAt: in.ExpiresAt,
		FamilyID: in.FamilyID, FamilyStartedAt: in.FamilyStartedAt,
	}
	m.rows = append(m.rows, row)
	return *row, nil
}

// Rotate is Revoke and Create under one lock, as the store does in one
// transaction. guard, when set, stands in for the account checks the store makes
// under the row lock.
func (m *memRefreshStore) Rotate(ctx context.Context, oldID string, in port.NewRefreshToken, tokenVersion int32) error {
	if m.guard != nil {
		if err := m.guard(in.UserID, tokenVersion); err != nil {
			return err
		}
	}
	m.rotateMu.Lock()
	defer m.rotateMu.Unlock()
	if _, err := m.Revoke(ctx, oldID); err != nil {
		return err
	}
	_, err := m.Create(ctx, in)
	return err
}

func (m *memRefreshStore) GetByHash(_ context.Context, hash string) (port.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.TokenHash == hash {
			return *r, nil
		}
	}
	return port.RefreshToken{}, port.ErrNotFound
}

func (m *memRefreshStore) Revoke(_ context.Context, id string) (port.RefreshToken, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.ID == id && r.RevokedAt == nil {
			at := m.now()
			r.RevokedAt = &at
			return *r, nil
		}
	}
	return port.RefreshToken{}, port.ErrNotFound
}

func (m *memRefreshStore) RevokeAllForUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.UserID == userID && r.RevokedAt == nil {
			at := m.now()
			r.RevokedAt = &at
		}
	}
	return nil
}

func (m *memRefreshStore) RevokeFamily(_ context.Context, familyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, r := range m.rows {
		if r.FamilyID == familyID && r.RevokedAt == nil {
			at := m.now()
			r.RevokedAt = &at
		}
	}
	return nil
}

// live reports whether the row for a raw token exists and is unrevoked.
func (m *memRefreshStore) live(raw string) bool {
	sum := sha256.Sum256([]byte(raw))
	r, err := m.GetByHash(context.Background(), hex.EncodeToString(sum[:]))
	return err == nil && r.RevokedAt == nil
}

type reuseHarness struct {
	uc    *Usecases
	store *memRefreshStore
	users *mockUserRepo
	now   time.Time
}

func newReuseHarness(t *testing.T) *reuseHarness {
	t.Helper()
	h := &reuseHarness{now: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	h.store = &memRefreshStore{now: func() time.Time { return h.now }}
	ur := &mockUserRepo{getByIDFn: func(context.Context, string) (port.User, error) {
		return makeUser(lifetimeUserID), nil
	}}
	h.users = ur
	h.uc = New(Deps{
		Stores:    &port.Stores{RefreshTokens: h.store, Users: ur},
		Tokens:    testJWT(t),
		Passwords: auth.NewPasswordHasher(),
		Now:       func() time.Time { return h.now },
	})
	return h
}

// signIn starts a new sign-in (a device) and returns its refresh token.
func (h *reuseHarness) signIn(t *testing.T) string {
	t.Helper()
	resp, err := h.uc.createSession(context.Background(), lifetimeUserID, "a@example.com")
	require.NoError(t, err)
	return resp.RefreshToken
}

func (h *reuseHarness) refresh(raw string) (*AuthResponse, error) {
	return h.uc.Refresh(context.Background(), raw)
}

// Two tabs that refresh with the same token at the same moment: one wins, the
// other is told the token was just rotated, and the winner keeps its session.
func TestRefreshReuse_ConcurrentDoubleRefreshKeepsTheWinnersSession(t *testing.T) {
	h := newReuseHarness(t)
	first := h.signIn(t)

	const n = 8
	var wg sync.WaitGroup
	resps := make([]*AuthResponse, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resps[i], errs[i] = h.refresh(first)
		}(i)
	}
	wg.Wait()

	var winner *AuthResponse
	for i := 0; i < n; i++ {
		if errs[i] == nil {
			require.Nil(t, winner, "exactly one concurrent refresh may succeed")
			winner = resps[i]
			continue
		}
		assert.ErrorIs(t, errs[i], ErrRefreshReused, "a loser is a benign race, not a revoked token")
	}
	require.NotNil(t, winner, "one refresh must win")

	assert.True(t, h.store.live(winner.RefreshToken), "the losers must not revoke the winner's new token")
	_, err := h.refresh(winner.RefreshToken)
	assert.NoError(t, err, "the winner keeps a working session")
}

func TestRefreshReuse_ReplayInsideTheGraceWindowIsABenignRace(t *testing.T) {
	h := newReuseHarness(t)
	first := h.signIn(t)
	rotated, err := h.refresh(first)
	require.NoError(t, err)

	h.now = h.now.Add(refreshReuseGrace - time.Second)
	_, err = h.refresh(first)

	require.ErrorIs(t, err, ErrRefreshReused)
	assert.True(t, h.store.live(rotated.RefreshToken), "a replay inside the window revokes nothing")
}

func TestRefreshReuse_ReplayAfterTheWindowRevokesOnlyThatFamily(t *testing.T) {
	for name, wait := range map[string]time.Duration{
		"exactly at the window": refreshReuseGrace,
		"well after":            time.Hour,
	} {
		t.Run(name, func(t *testing.T) {
			h := newReuseHarness(t)
			laptop := h.signIn(t)
			phone := h.signIn(t)
			rotated, err := h.refresh(laptop)
			require.NoError(t, err)

			h.now = h.now.Add(wait)
			_, err = h.refresh(laptop) // the old laptop token comes back: theft signal

			require.EqualError(t, err, "refresh token has been revoked")
			require.NotErrorIs(t, err, ErrRefreshReused)
			assert.False(t, h.store.live(rotated.RefreshToken), "the laptop's sign-in chain is revoked")
			assert.True(t, h.store.live(phone), "another device's sign-in survives")
			_, err = h.refresh(phone)
			assert.NoError(t, err, "the phone keeps refreshing")
		})
	}
}

// A refresh rotates under the token generation it read before it spent the old
// token, so a credential change that commits afterwards makes the store refuse
// the successor.
func TestRefresh_RotatesUnderTheGenerationItRead(t *testing.T) {
	h := newReuseHarness(t)
	first := h.signIn(t)
	h.users.getByIDFn = func(context.Context, string) (port.User, error) {
		u := makeUser(lifetimeUserID)
		u.TokenVersion = 7
		return u, nil
	}
	var seen int32
	h.store.guard = func(_ string, version int32) error {
		seen = version
		return nil
	}

	resp, err := h.refresh(first)

	require.NoError(t, err)
	assert.Equal(t, int32(7), seen, "the store checks the generation the refresh read")
	ident, err := h.uc.deps.Tokens.(*auth.JWTAuthenticator).Authenticate(context.Background(), resp.Token)
	require.NoError(t, err)
	require.NotNil(t, ident.TokenVersion)
	assert.Equal(t, int32(7), *ident.TokenVersion, "the access token carries that same generation")
}

func TestRefresh_AStaleGenerationStoresNoSuccessor(t *testing.T) {
	h := newReuseHarness(t)
	first := h.signIn(t)
	h.store.guard = func(string, int32) error { return port.ErrSessionStale }

	_, err := h.refresh(first)

	require.EqualError(t, err, "refresh token has been revoked")
	require.NotErrorIs(t, err, ErrRefreshReused)
	assert.Len(t, h.store.rows, 1, "no successor token is stored")
	assert.True(t, h.store.live(first), "the refused refresh left the old token alone")
}
