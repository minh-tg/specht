//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPostgresRevoker_SharedAcrossInstancesAndPrunesBoundedBatch(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	first := NewPostgresRevoker(repos.pool)
	second := NewPostgresRevoker(repos.pool)
	require.NoError(t, first.Revoke(ctx, "shared-jti", time.Now().Add(time.Hour)))

	revoked, err := second.IsRevoked(ctx, "shared-jti")
	require.NoError(t, err)
	require.True(t, revoked, "a second store instance must observe the persisted revocation")
	require.NoError(t, first.Revoke(ctx, "already-expired", time.Now().Add(-time.Minute)))
	revoked, err = second.IsRevoked(ctx, "already-expired")
	require.NoError(t, err)
	require.False(t, revoked, "expired revocations must not be considered active")

	_, err = repos.pool.Exec(ctx, `
		INSERT INTO revoked_access_tokens (jti, expires_at)
		SELECT 'expired-' || n, NOW() - INTERVAL '1 minute'
		FROM generate_series(1, 1005) AS n`)
	require.NoError(t, err)

	_, err = second.IsRevoked(ctx, "not-present")
	require.NoError(t, err)

	var remaining int
	err = repos.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM revoked_access_tokens
		WHERE jti LIKE 'expired-%'`).Scan(&remaining)
	require.NoError(t, err)
	require.Equal(t, 5, remaining, "pruning must delete at most the configured batch size")

	var active int
	err = repos.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM revoked_access_tokens
		WHERE jti = 'shared-jti' AND expires_at > NOW()`).Scan(&active)
	require.NoError(t, err)
	require.Equal(t, 1, active, "pruning must leave unexpired revocations intact")
}
