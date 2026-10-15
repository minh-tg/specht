//go:build integration

package repo

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstanceSecrets_EnsureKeepsTheFirstValue(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)

	first, err := stores.InstanceSecrets.Ensure(ctx, "fingerprint-key", []byte("first-value-first-value-first-val"))
	require.NoError(t, err)
	assert.Equal(t, []byte("first-value-first-value-first-val"), first)

	second, err := stores.InstanceSecrets.Ensure(ctx, "fingerprint-key", []byte("another-value-another-value-anoth"))
	require.NoError(t, err)
	assert.Equal(t, first, second, "a later caller gets the stored value, not its own")

	other, err := stores.InstanceSecrets.Ensure(ctx, "another-secret", []byte("x"))
	require.NoError(t, err)
	assert.Equal(t, []byte("x"), other, "each name has its own value")
}

func TestInstanceSecrets_ConcurrentFirstUseAgreesOnOneValue(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	stores := NewPortStores(repos.pool)

	const callers = 12
	results := make([][]byte, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			candidate := []byte{byte('a' + i), byte('a' + i), byte('a' + i), byte('a' + i)}
			got, err := stores.InstanceSecrets.Ensure(context.Background(), "fingerprint-key", candidate)
			if err == nil {
				results[i] = got
			}
		}(i)
	}
	wg.Wait()

	for i := range results {
		require.NotEmpty(t, results[i], "caller %d got a value", i)
		assert.Equal(t, results[0], results[i], "every caller sees the same key")
	}
}
