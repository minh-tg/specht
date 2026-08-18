package repo

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

// WatcherRepo is the persistence surface for the CVE feed watcher's poll
// watermark (watcher_state, migration 000017).
type WatcherRepo interface {
	// GetState returns the single watcher_state row, or pgx.ErrNoRows when
	// no poll has ever completed (the cold-start condition).
	GetState(ctx context.Context) (sqlc.WatcherState, error)
	// UpdateState advances the watermark to ts. The row is created on the
	// first call; the daemon only calls this after a fully successful poll.
	UpdateState(ctx context.Context, ts time.Time) error
}

type pgWatcherRepo struct {
	q *sqlc.Queries
}

func newWatcherRepo(q *sqlc.Queries) *pgWatcherRepo {
	return &pgWatcherRepo{q: q}
}

func (r *pgWatcherRepo) GetState(ctx context.Context) (sqlc.WatcherState, error) {
	return r.q.GetWatcherState(ctx)
}

func (r *pgWatcherRepo) UpdateState(ctx context.Context, ts time.Time) error {
	return r.q.UpdateWatcherState(ctx, pgtype.Timestamptz{Time: ts, Valid: true})
}
