//go:build integration

package repo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// A transaction PostgreSQL ends as a deadlock victim comes back marked as
// retryable, and still unwraps to the database error.
func TestDeadlockVictimIsMarkedRetryable(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	first := newUser(t, repos, "first@test.com", "member")
	second := newUser(t, repos, "second@test.com", "member")

	other, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = other.Rollback(ctx) }()
	_, err = other.Exec(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, uuid.MustParse(first.ID))
	require.NoError(t, err)

	// The transaction under test takes the second row, then waits for the
	// first. It started waiting before the other one does, so its deadlock
	// check runs first and it is the one aborted.
	victim := make(chan error, 1)
	go func() {
		victim <- repos.WithTx(ctx, func(q *sqlc.Queries) error {
			if _, err := q.LockUserForMembership(ctx, mustParseID(second.ID)); err != nil {
				return err
			}
			_, err := q.LockUserForMembership(ctx, mustParseID(first.ID))
			return err
		})
	}()
	time.Sleep(300 * time.Millisecond)
	go func() {
		_, _ = other.Exec(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, uuid.MustParse(second.ID))
	}()

	select {
	case err := <-victim:
		require.ErrorIs(t, err, port.ErrRetry)
		var pgErr *pgconn.PgError
		require.True(t, errors.As(err, &pgErr))
		assert.Equal(t, "40P01", pgErr.Code)
	case <-time.After(15 * time.Second):
		t.Fatal("no deadlock was reported")
	}
}
