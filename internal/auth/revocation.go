package auth

import (
	"sync"
	"time"
)

// Revoker records access-token JTIs that must no longer authenticate.
type Revoker interface {
	Revoke(jti string, exp time.Time) error
	IsRevoked(jti string) bool
}

// TokenRevoker revokes a bearer access token after verifying its signature.
type TokenRevoker interface {
	RevokeToken(token string) error
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

func (r *MemoryRevoker) Revoke(jti string, exp time.Time) error {
	if jti == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revoked[jti] = exp
	return nil
}

func (r *MemoryRevoker) IsRevoked(jti string) bool {
	now := time.Now()
	r.mu.RLock()
	exp, ok := r.revoked[jti]
	r.mu.RUnlock()
	if !ok {
		return false
	}
	if !exp.IsZero() && !now.Before(exp) {
		r.mu.Lock()
		delete(r.revoked, jti)
		r.mu.Unlock()
		return false
	}
	return true
}
