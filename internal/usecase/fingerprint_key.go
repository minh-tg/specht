package usecase

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
)

const (
	// fingerprintKeySecret names the stored key.
	fingerprintKeySecret = "fingerprint-key"
	// fingerprintKeyBytes is the size of a new key: 256 bits.
	fingerprintKeyBytes = 32
	// minFingerprintKeyBytes is the shortest stored key accepted. Anything shorter was
	// not made here, and hashing secrets with it would not protect them.
	minFingerprintKeyBytes = 16
)

// instanceFingerprintKey returns the key scanners hash secrets with, making and
// storing one the first time. It lives in the database so a restart or a restore
// keeps it: a different key would give every secret finding a new identity.
func (u *Usecases) instanceFingerprintKey(ctx context.Context) ([]byte, error) {
	u.keyMu.Lock()
	defer u.keyMu.Unlock()
	if len(u.fingerprintKey) > 0 {
		return u.fingerprintKey, nil
	}
	if u.deps.Stores == nil || u.deps.Stores.InstanceSecrets == nil {
		return nil, errors.New("load the instance key: no secret store is configured")
	}
	candidate := make([]byte, fingerprintKeyBytes)
	if _, err := rand.Read(candidate); err != nil {
		return nil, fmt.Errorf("make an instance key: %w", err)
	}
	key, err := u.deps.Stores.InstanceSecrets.Ensure(ctx, fingerprintKeySecret, candidate)
	if err != nil {
		return nil, fmt.Errorf("load the instance key: %w", err)
	}
	if len(key) < minFingerprintKeyBytes {
		return nil, fmt.Errorf("load the instance key: the stored key is %d bytes, want at least %d", len(key), minFingerprintKeyBytes)
	}
	u.fingerprintKey = key
	return key, nil
}
