package repo

import (
	"context"

	"github.com/vulnserve/vulnserve/internal/db/sqlc"
)

type pgProjectRepo struct {
	q *sqlc.Queries
}

func newProjectRepo(q *sqlc.Queries) *pgProjectRepo {
	return &pgProjectRepo{q: q}
}

func (r *pgProjectRepo) Create(ctx context.Context, arg sqlc.CreateProjectParams) (sqlc.Project, error) {
	return r.q.CreateProject(ctx, arg)
}

func (r *pgProjectRepo) List(ctx context.Context) ([]sqlc.Project, error) {
	return r.q.ListProjects(ctx)
}

func (r *pgProjectRepo) GetBySlug(ctx context.Context, slug string) (sqlc.Project, error) {
	return r.q.GetProjectBySlug(ctx, slug)
}
