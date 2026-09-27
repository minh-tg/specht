package auth

import (
	"context"
	"sync"
	"time"
)

// Revoker records access-token JTIs that must no longer authenticate.
type Revoker interface {
	Revoke(ctx context.Context, jti string, exp time.Time) error
	IsRevoked(ctx context.Context, jti string) (bool, error)
}

// TokenRevoker revokes a bearer access token after verifying its signature.
type TokenRevoker interface {
	RevokeTokenContext(ctx context.Context, token string) error
}

// MemoryRevoker stores revocations in process memory. Entries are bounded by
// token expiry and are suitable for a single server instance.
type MemoryRevoker struct {
	mu      sync.RWMutex
	revoked map[string]time.Time
}

func NewMemoryRevoker() *MemoryRevoker {
	return &MemoryRevoker{revoked: make(map[string]time.Time)}
}

func (r *MemoryRevoker) Revoke(_ context.Context, jti string, exp time.Time) error {
	if jti == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[jti] = exp
	return nil
}

func (r *MemoryRevoker) IsRevoked(_ context.Context, jti string) (bool, error) {
	now := time.Now()
	r.mu.RLock()
	exp, ok := r.revoked[jti]
	r.mu.RUnlock()
	if !ok {
		return false, nil
	}
	if !exp.IsZero() && !now.Before(exp) {
		r.mu.Lock()
		delete(r.revoked, jti)
		r.mu.Unlock()
		return false, nil
	}
	return true, nil
}
