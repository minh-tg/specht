package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type memorySSOCodeStore struct {
	mu    sync.Mutex
	codes map[string]port.SSOCode
}

func newMemorySSOCodeStore() *memorySSOCodeStore {
	return &memorySSOCodeStore{codes: make(map[string]port.SSOCode)}
}

func (m *memorySSOCodeStore) Create(ctx context.Context, codeHash, userID, browserBinding string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[codeHash] = port.SSOCode{
		CodeHash:       codeHash,
		UserID:         userID,
		BrowserBinding: browserBinding,
		ExpiresAt:      expiresAt,
	}
	return nil
}

func (m *memorySSOCodeStore) Lookup(ctx context.Context, codeHash string, now time.Time) (port.SSOCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	code, ok := m.codes[codeHash]
	if !ok || !now.Before(code.ExpiresAt) {
		return port.SSOCode{}, port.ErrNotFound
	}
	return code, nil
}

func (m *memorySSOCodeStore) Consume(ctx context.Context, codeHash string, now time.Time) (port.SSOCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	code, ok := m.codes[codeHash]
	if !ok || !now.Before(code.ExpiresAt) {
		return port.SSOCode{}, port.ErrNotFound
	}
	delete(m.codes, codeHash)
	return code, nil
}

// ssoExchangeFixture is a usecase wired to in-memory stores with one active user.
type ssoExchangeFixture struct {
	uc       *Usecases
	ssoStore *memorySSOCodeStore
	userID   string
}

func newSSOExchangeFixture(t *testing.T) ssoExchangeFixture {
	t.Helper()
	user := port.User{
		ID:    "user-123",
		Email: "alice@example.com",
		Role:  "member",
	}

	userStore := &mockUserRepo{
		getByIDFn: func(ctx context.Context, id string) (port.User, error) {
			if id == user.ID {
				return user, nil
			}
			return port.User{}, port.ErrNotFound
		},
	}
	refreshStore := &mockRefreshTokenRepo{
		createFn: func(ctx context.Context, in port.NewRefreshToken) (port.RefreshToken, error) {
			return makeRefreshToken(false), nil
		},
	}
	ssoStore := newMemorySSOCodeStore()

	jwtAuth, err := auth.NewJWTAuthenticator("01234567890123456789012345678901")
	require.NoError(t, err)

	uc := New(Deps{
		Stores: &port.Stores{
			Users:         userStore,
			RefreshTokens: refreshStore,
			SSOCodes:      ssoStore,
		},
		Tokens: jwtAuth,
	})
	return ssoExchangeFixture{uc: uc, ssoStore: ssoStore, userID: user.ID}
}

func TestSSOExchangeCode_Flow(t *testing.T) {
	ctx := context.Background()
	f := newSSOExchangeFixture(t)
	uc, ssoStore, userID := f.uc, f.ssoStore, f.userID

	browser := auth.BrowserBinding("secret-of-the-login-cookie")
	login := auth.PresentedLogin{Name: "sso_state_login", Binding: browser}

	t.Run("creates and exchanges code for access and refresh tokens", func(t *testing.T) {
		code, err := uc.CreateSSOExchangeCode(ctx, userID, browser)
		require.NoError(t, err)
		require.NotEmpty(t, code)

		// Verify stored hash matches code
		hash := sha256.Sum256([]byte(code))
		hashStr := hex.EncodeToString(hash[:])
		stored, ok := ssoStore.codes[hashStr]
		require.True(t, ok)
		assert.Equal(t, userID, stored.UserID)
		assert.Equal(t, browser, stored.BrowserBinding, "the code keeps the browser it was issued to")

		// Exchange code
		resp, matched, err := uc.ExchangeSSOCode(ctx, code, []auth.PresentedLogin{login})
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Token)
		assert.NotEmpty(t, resp.RefreshToken)
		assert.Equal(t, userID, resp.UserID)
		assert.Equal(t, "alice@example.com", resp.Email)
		assert.Equal(t, login.Name, matched.Name, "the matched login is the one to clear")

		// Code is now consumed: second exchange fails (single-use)
		_, _, err = uc.ExchangeSSOCode(ctx, code, []auth.PresentedLogin{login})
		require.ErrorIs(t, err, auth.ErrInvalidCredential)
	})

	t.Run("fails on non-existent or empty code", func(t *testing.T) {
		_, _, err := uc.ExchangeSSOCode(ctx, "", []auth.PresentedLogin{login})
		require.ErrorIs(t, err, auth.ErrInvalidCredential)

		_, _, err = uc.ExchangeSSOCode(ctx, "invalid-random-code", []auth.PresentedLogin{login})
		require.ErrorIs(t, err, auth.ErrInvalidCredential)
	})

	t.Run("fails on expired code", func(t *testing.T) {
		code, err := uc.CreateSSOExchangeCode(ctx, userID, browser)
		require.NoError(t, err)

		// Manually expire code
		hash := sha256.Sum256([]byte(code))
		hashStr := hex.EncodeToString(hash[:])
		expired := ssoStore.codes[hashStr]
		expired.ExpiresAt = time.Now().Add(-1 * time.Minute)
		ssoStore.codes[hashStr] = expired

		_, _, err = uc.ExchangeSSOCode(ctx, code, []auth.PresentedLogin{login})
		require.ErrorIs(t, err, auth.ErrInvalidCredential)
	})
}

// A code belongs to the browser that started its login. Redeeming it from any
// other browser is refused without spending the code, so the code is not burned
// by a wrong browser, and the owning browser can still finish the login.
func TestSSOExchangeCode_NeedsTheStartingBrowser(t *testing.T) {
	ctx := context.Background()

	const victimSecret = "dmljdGltLXNlY3JldA"
	victim := auth.PresentedLogin{Name: "sso_state_victim", Binding: auth.BrowserBinding(victimSecret)}
	otherBrowser := auth.PresentedLogin{Name: "sso_state_other", Binding: auth.BrowserBinding("b3RoZXItc2VjcmV0")}
	victimCookie := func(expires time.Time) *http.Cookie {
		return &http.Cookie{
			Name:  victim.Name,
			Value: fmt.Sprintf("v1.%s.%d.L3Byb2plY3Rz.c2lnbmF0dXJl", victimSecret, expires.Unix()),
		}
	}

	t.Run("a browser with no login cookie is refused and the code survives", func(t *testing.T) {
		f := newSSOExchangeFixture(t)
		code, err := f.uc.CreateSSOExchangeCode(ctx, f.userID, victim.Binding)
		require.NoError(t, err)

		resp, _, err := f.uc.ExchangeSSOCode(ctx, code, nil)
		require.ErrorIs(t, err, auth.ErrSSOBrowserMismatch)
		assert.Nil(t, resp, "a refused exchange issues no session")

		resp, matched, err := f.uc.ExchangeSSOCode(ctx, code, []auth.PresentedLogin{victim})
		require.NoError(t, err, "the browser that started the login still redeems the code")
		assert.Equal(t, f.userID, resp.UserID)
		assert.Equal(t, victim.Name, matched.Name)
	})

	t.Run("a browser holding only another login's cookie is refused and the code survives", func(t *testing.T) {
		f := newSSOExchangeFixture(t)
		code, err := f.uc.CreateSSOExchangeCode(ctx, f.userID, victim.Binding)
		require.NoError(t, err)

		_, _, err = f.uc.ExchangeSSOCode(ctx, code, []auth.PresentedLogin{otherBrowser})
		require.ErrorIs(t, err, auth.ErrSSOBrowserMismatch)

		_, matched, err := f.uc.ExchangeSSOCode(ctx, code, []auth.PresentedLogin{otherBrowser, victim})
		require.NoError(t, err)
		assert.Equal(t, victim.Name, matched.Name, "the matching cookie is picked out of several")
	})

	t.Run("an expired login cookie is refused and the code survives", func(t *testing.T) {
		f := newSSOExchangeFixture(t)
		code, err := f.uc.CreateSSOExchangeCode(ctx, f.userID, victim.Binding)
		require.NoError(t, err)

		// The cookie carries the right secret but has passed its expiry.
		expired := auth.PresentedLogins([]*http.Cookie{victimCookie(time.Now().Add(-time.Second))}, time.Now())
		require.Empty(t, expired, "an expired cookie is not presented")

		_, _, err = f.uc.ExchangeSSOCode(ctx, code, expired)
		require.ErrorIs(t, err, auth.ErrSSOBrowserMismatch)

		_, _, err = f.uc.ExchangeSSOCode(ctx, code, auth.PresentedLogins([]*http.Cookie{victimCookie(time.Now().Add(time.Minute))}, time.Now()))
		require.NoError(t, err)
	})

	t.Run("a code issued without a binding is refused for every browser", func(t *testing.T) {
		f := newSSOExchangeFixture(t)
		code, err := f.uc.CreateSSOExchangeCode(ctx, f.userID, "")
		require.NoError(t, err)

		_, _, err = f.uc.ExchangeSSOCode(ctx, code, []auth.PresentedLogin{victim})
		require.ErrorIs(t, err, auth.ErrSSOBrowserMismatch)
	})
}
