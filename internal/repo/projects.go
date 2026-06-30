package repo

import (
	"context"

	"github.com/vulnserve/vulnserve/internal/db/sqlc"
)

type ProjectRepo struct {
	q *sqlc.Queries
}

func NewProjectRepo(q *sqlc.Queries) *ProjectRepo {
	return &ProjectRepo{q: q}
}

func (r *ProjectRepo) GetBySlug(ctx context.Context, slug string) (sqlc.Project, error) {
	return r.q.GetProjectBySlug(ctx, slug)
}
