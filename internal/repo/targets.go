package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
)

type pgTargetRepo struct {
	q *sqlc.Queries
}

func (r *pgTargetRepo) Upsert(ctx context.Context, arg sqlc.UpsertTargetParams) (sqlc.Target, error) {
	return r.q.UpsertTarget(ctx, arg)
}

func (r *pgTargetRepo) List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Target, error) {
	return r.q.ListTargets(ctx, projectID)
}

func (r *pgTargetRepo) GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Target, error) {
	return r.q.GetTarget(ctx, sqlc.GetTargetParams{ID: id, ProjectID: projectID})
}

func (r *pgTargetRepo) Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Target, error) {
	return r.q.DeleteTarget(ctx, sqlc.DeleteTargetParams{ID: id, ProjectID: projectID})
}
