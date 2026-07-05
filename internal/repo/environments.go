package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

type pgEnvironmentRepo struct {
	q *sqlc.Queries
}

func (r *pgEnvironmentRepo) Upsert(ctx context.Context, arg sqlc.UpsertEnvironmentParams) (sqlc.Environment, error) {
	return r.q.UpsertEnvironment(ctx, arg)
}

func (r *pgEnvironmentRepo) List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Environment, error) {
	return r.q.ListEnvironments(ctx, projectID)
}

func (r *pgEnvironmentRepo) GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Environment, error) {
	return r.q.GetEnvironment(ctx, sqlc.GetEnvironmentParams{ID: id, ProjectID: projectID})
}

func (r *pgEnvironmentRepo) Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Environment, error) {
	return r.q.DeleteEnvironment(ctx, sqlc.DeleteEnvironmentParams{ID: id, ProjectID: projectID})
}
