package scanner

import (
	"context"
	"errors"
	"fmt"
	"slices"
)

type fingerprintKeyContext struct{}

// ErrFingerprintKeyRequired is returned by a scanner that identifies findings by
// a keyed hash when the caller gave it no key. It fails rather than falling back
// to an unkeyed hash, which would let anyone with the database guess weak secrets.
var ErrFingerprintKeyRequired = errors.New("a fingerprint key is required")

// KeyRequired builds the error a scanner returns when it needs a key it was not given.
func KeyRequired(scanner string) error {
	return fmt.Errorf("%s: %w", scanner, ErrFingerprintKeyRequired)
}

// KeyedScanner is implemented by scanners whose finding identity hashes secret
// material with the instance's key, so the secret itself is never stored. Ingest
// hands the key to these scanners only.
type KeyedScanner interface {
	UsesFingerprintKey() bool
}

// UsesFingerprintKey reports whether s wants the instance fingerprint key.
func UsesFingerprintKey(s Scanner) bool {
	if s == nil {
		return false
	}
	k, ok := s.(KeyedScanner)
	return ok && k.UsesFingerprintKey()
}

// WithFingerprintKey returns a context that carries a copy of key.
func WithFingerprintKey(ctx context.Context, key []byte) context.Context {
	return context.WithValue(ctx, fingerprintKeyContext{}, slices.Clone(key))
}

// FingerprintKey returns a copy of the key in ctx. An empty key counts as none.
func FingerprintKey(ctx context.Context) ([]byte, bool) {
	key, _ := ctx.Value(fingerprintKeyContext{}).([]byte)
	if len(key) == 0 {
		return nil, false
	}
	return slices.Clone(key), true
}
