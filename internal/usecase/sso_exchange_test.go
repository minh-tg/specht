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

type memorySSOCodeStore struct {
	mu    sync.Mutex
	codes map[string]port.SSOCode
}

func newMemorySSOCodeStore() *memorySSOCodeStore {
	return &memorySSOCodeStore{codes: make(map[string]port.SSOCode)}
}

func (m *memorySSOCodeStore) Create(ctx context.Context, codeHash, userID, email, role string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[codeHash] = port.SSOCode{
		CodeHash:  codeHash,
		UserID:    userID,
		Email:     email,
		Role:      role,
		ExpiresAt: expiresAt,
	}
	return nil
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

func TestSSOExchangeCode_Flow(t *testing.T) {
	ctx := context.Background()
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
		createFn: func(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (port.RefreshToken, error) {
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

	t.Run("creates and exchanges code for access and refresh tokens", func(t *testing.T) {
		code, err := uc.CreateSSOExchangeCode(ctx, user.ID, user.Email, user.Role)
		require.NoError(t, err)
		require.NotEmpty(t, code)

		// Verify stored hash matches code
		hash := sha256.Sum256([]byte(code))
		hashStr := hex.EncodeToString(hash[:])
		stored, ok := ssoStore.codes[hashStr]
		require.True(t, ok)
		assert.Equal(t, user.ID, stored.UserID)
		assert.Equal(t, user.Email, stored.Email)

		// Exchange code
		resp, err := uc.ExchangeSSOCode(ctx, code)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Token)
		assert.NotEmpty(t, resp.RefreshToken)
		assert.Equal(t, user.ID, resp.UserID)
		assert.Equal(t, user.Email, resp.Email)

		// Code is now consumed: second exchange fails (single-use)
		_, err = uc.ExchangeSSOCode(ctx, code)
		require.ErrorIs(t, err, auth.ErrInvalidCredential)
	})

	t.Run("fails on non-existent or empty code", func(t *testing.T) {
		_, err := uc.ExchangeSSOCode(ctx, "")
		require.ErrorIs(t, err, auth.ErrInvalidCredential)

		_, err = uc.ExchangeSSOCode(ctx, "invalid-random-code")
		require.ErrorIs(t, err, auth.ErrInvalidCredential)
	})

	t.Run("fails on expired code", func(t *testing.T) {
		code, err := uc.CreateSSOExchangeCode(ctx, user.ID, user.Email, user.Role)
		require.NoError(t, err)

		// Manually expire code
		hash := sha256.Sum256([]byte(code))
		hashStr := hex.EncodeToString(hash[:])
		expired := ssoStore.codes[hashStr]
		expired.ExpiresAt = time.Now().Add(-1 * time.Minute)
		ssoStore.codes[hashStr] = expired

		_, err = uc.ExchangeSSOCode(ctx, code)
		require.ErrorIs(t, err, auth.ErrInvalidCredential)
	})
}
