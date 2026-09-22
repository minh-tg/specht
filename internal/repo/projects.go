package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
)

type pgProjectRepo struct {
	q *sqlc.Queries
}

func (r *pgProjectRepo) Create(ctx context.Context, arg sqlc.CreateProjectParams) (sqlc.Project, error) {
	return r.q.CreateProject(ctx, arg)
}

func (r *pgProjectRepo) List(ctx context.Context) ([]sqlc.Project, error) {
	return r.q.ListProjects(ctx)
}

func (r *pgProjectRepo) ListByIDs(ctx context.Context, ids []pgtype.UUID) ([]sqlc.Project, error) {
	return r.q.ListProjectsByIDs(ctx, ids)
}

func (r *pgProjectRepo) GetBySlug(ctx context.Context, slug string) (sqlc.Project, error) {
	return r.q.GetProjectBySlug(ctx, slug)
}
