package repo

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
)

// WatcherRepo is the persistence surface for the CVE feed watcher's poll
// watermark and health (watcher_state, migrations 000017/000020).
type WatcherRepo interface {
	// GetState returns the single watcher_state row, or pgx.ErrNoRows when
	// no poll has ever completed (the cold-start condition).
	GetState(ctx context.Context) (sqlc.WatcherState, error)
	// UpdateState advances the watermark to ts. The row is created on the
	// first call; the daemon only calls this after a fully successful poll.
	UpdateState(ctx context.Context, ts time.Time) error
	// RecordAttempt records a poll attempt start (no error). Used for
	// operator visibility into watcher health.
	RecordAttempt(ctx context.Context, ts time.Time) error
	// RecordFailure records a failed poll: the error text and a bumped
	// consecutive-failure counter, with the attempt time.
	RecordFailure(ctx context.Context, errText string, ts time.Time) error
	// ResetFailure clears the error state after a successful poll, keeping
	// the attempt time.
	ResetFailure(ctx context.Context) error
	// GetProjectConfig returns a project's per-project watcher enable +
	// interval override.
	GetProjectConfig(ctx context.Context, projectID pgtype.UUID) (sqlc.GetProjectWatcherConfigRow, error)
	// GetProjectState returns a project's own watermark (watcher_project_state,
	// migration 000023) or pgx.ErrNoRows when it has never polled.
	GetProjectState(ctx context.Context, projectID pgtype.UUID) (sqlc.WatcherProjectState, error)
	// UpsertProjectState advances one project's watermark after a fully
	// successful poll of that project.
	UpsertProjectState(ctx context.Context, projectID pgtype.UUID, ts time.Time) error
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

func (r *pgWatcherRepo) RecordAttempt(ctx context.Context, ts time.Time) error {
	return r.q.RecordWatcherAttempt(ctx, sqlc.RecordWatcherAttemptParams{
		Column1:             pgtype.Timestamptz{Time: ts, Valid: true},
		LastError:           pgtype.Text{Valid: false},
		ConsecutiveFailures: 0,
	})
}

func (r *pgWatcherRepo) RecordFailure(ctx context.Context, errText string, ts time.Time) error {
	return r.q.IncrementWatcherFailure(ctx, sqlc.IncrementWatcherFailureParams{
		LastError: pgtype.Text{String: errText, Valid: true},
		Column2:   pgtype.Timestamptz{Time: ts, Valid: true},
	})
}

func (r *pgWatcherRepo) ResetFailure(ctx context.Context) error {
	return r.q.ResetWatcherFailure(ctx)
}

func (r *pgWatcherRepo) GetProjectConfig(ctx context.Context, projectID pgtype.UUID) (sqlc.GetProjectWatcherConfigRow, error) {
	return r.q.GetProjectWatcherConfig(ctx, projectID)
}

func (r *pgWatcherRepo) GetProjectState(ctx context.Context, projectID pgtype.UUID) (sqlc.WatcherProjectState, error) {
	return r.q.GetProjectWatcherState(ctx, projectID)
}

func (r *pgWatcherRepo) UpsertProjectState(ctx context.Context, projectID pgtype.UUID, ts time.Time) error {
	return r.q.UpsertProjectWatcherState(ctx, sqlc.UpsertProjectWatcherStateParams{
		ProjectID: projectID,
		Column2:   pgtype.Timestamptz{Time: ts, Valid: true},
	})
}
