package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A key from FINGERPRINT_KEY is used as given and the secret store is never
// touched, so it is never written to the database.
func TestInstanceFingerprintKey_ConfiguredKeyBypassesTheStore(t *testing.T) {
	want := []byte("0123456789abcdef0123456789abcdef")
	uc := New(Deps{FingerprintKey: want})

	got, err := uc.instanceFingerprintKey(context.Background())
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

// Without a configured key the key comes from the store, which this test does not provide.
func TestInstanceFingerprintKey_WithoutAKeyNeedsTheStore(t *testing.T) {
	uc := New(Deps{})

	_, err := uc.instanceFingerprintKey(context.Background())
	assert.ErrorContains(t, err, "no secret store")
}
