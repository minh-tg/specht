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
	mu    sync.Mutex
	now   func() time.Time
	rows  []*port.RefreshToken
	guard func(userID string, tokenVersion int32) error
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

// Rotate spends the old row and appends the successor under one lock, as the
// store does in one transaction, so a reader never sees the old token spent
// without its successor. guard, when set, stands in for the account checks the
// store makes under the row lock.
func (m *memRefreshStore) Rotate(_ context.Context, oldID string, in port.NewRefreshToken, tokenVersion int32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.guard != nil {
		if err := m.guard(in.UserID, tokenVersion); err != nil {
			return err
		}
	}
	var old *port.RefreshToken
	for _, r := range m.rows {
		if r.ID == oldID && r.RevokedAt == nil {
			old = r
		}
	}
	if old == nil {
		return port.ErrNotFound
	}
	at := m.now()
	old.RevokedAt = &at
	m.rows = append(m.rows, &port.RefreshToken{
		ID: "row-" + in.TokenHash[:8], UserID: in.UserID, TokenHash: in.TokenHash, ExpiresAt: in.ExpiresAt,
		FamilyID: in.FamilyID, FamilyStartedAt: in.FamilyStartedAt,
	})
	return nil
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

// Two refreshes with the same token at the same moment: one wins, the others
// are told the token was already used. A second use cannot be told from theft,
// so the chain is revoked, the winner's successor with it.
func TestRefreshReuse_ConcurrentDoubleRefreshRevokesTheChain(t *testing.T) {
	h := newReuseHarness(t)
	first := h.signIn(t)
	other := h.signIn(t)

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
		assert.ErrorIs(t, errs[i], ErrRefreshReused)
	}
	require.NotNil(t, winner, "one refresh must win")

	assert.False(t, h.store.live(winner.RefreshToken), "the chain is revoked, the winner's successor included")
	assert.True(t, h.store.live(other), "another sign-in is a separate chain and survives")
}

// A thief who refreshes first gets a successor. The owner's refresh with the
// same token is the second use, and it takes the thief's successor with it
// instead of being served as a retry.
func TestRefreshReuse_TheSecondUseRevokesTheFirstUsersSuccessor(t *testing.T) {
	h := newReuseHarness(t)
	stolen := h.signIn(t)
	thief, err := h.refresh(stolen)
	require.NoError(t, err)

	h.now = h.now.Add(time.Second)
	_, err = h.refresh(stolen) // the owner, a second later

	require.ErrorIs(t, err, ErrRefreshReused)
	assert.False(t, h.store.live(thief.RefreshToken), "the thief does not keep the session")
}

// The grace window is zero: a replay is theft at any delay. The 11 second case
// sits just past the old 10 second window and the hour case catches a window
// raised to an hour, so a longer window fails this test.
func TestRefreshReuse_ReplayRevokesOnlyThatFamilyAtAnyDelay(t *testing.T) {
	assert.Zero(t, refreshReuseGrace, "a grace window lets a thief win the race against the owner")

	for name, wait := range map[string]time.Duration{
		"at once":         0,
		"a second later":  time.Second,
		"eleven seconds":  11 * time.Second,
		"an hour later":   time.Hour,
		"well after that": 6 * 24 * time.Hour,
	} {
		t.Run(name, func(t *testing.T) {
			h := newReuseHarness(t)
			laptop := h.signIn(t)
			phone := h.signIn(t)
			rotated, err := h.refresh(laptop)
			require.NoError(t, err)

			h.now = h.now.Add(wait)
			_, err = h.refresh(laptop) // the old laptop token comes back: theft signal

			require.ErrorIs(t, err, ErrRefreshReused)
			assert.False(t, h.store.live(rotated.RefreshToken), "the laptop's sign-in chain is revoked")
			assert.True(t, h.store.live(phone), "another device's sign-in survives")
			_, err = h.refresh(phone)
			assert.NoError(t, err, "the phone keeps refreshing")
		})
	}
}

// Signing out with a token a refresh already spent is a replay like any other:
// it revokes the chain, so a thief's copy cannot be used to probe the session
// without consequence, and the caller still gets its logout.
func TestLogout_StaleTokenRunsTheReusePath(t *testing.T) {
	h := newReuseHarness(t)
	laptop := h.signIn(t)
	phone := h.signIn(t)
	rotated, err := h.refresh(laptop)
	require.NoError(t, err)

	require.NoError(t, h.uc.Logout(context.Background(), laptop))

	assert.False(t, h.store.live(rotated.RefreshToken), "the successor of the stale token is revoked")
	assert.True(t, h.store.live(phone), "another sign-in survives")
}

func TestLogout_CurrentTokenEndsOnlyItsOwnSession(t *testing.T) {
	h := newReuseHarness(t)
	laptop := h.signIn(t)
	phone := h.signIn(t)

	require.NoError(t, h.uc.Logout(context.Background(), laptop))

	assert.False(t, h.store.live(laptop))
	assert.True(t, h.store.live(phone))
	assert.NoError(t, h.uc.Logout(context.Background(), "unknown-token"), "an unknown token is not an error")
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
