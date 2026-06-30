package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/vulnserve/vulnserve/internal/db/sqlc"
)

type pgAPIKeyRepo struct {
	q *sqlc.Queries
}

func (r *pgAPIKeyRepo) Create(ctx context.Context, arg sqlc.CreateAPIKeyParams) (sqlc.ApiKey, error) {
	return r.q.CreateAPIKey(ctx, arg)
}

func (r *pgAPIKeyRepo) ListByProject(ctx context.Context, projectID pgtype.UUID) ([]sqlc.ListAPIKeysByProjectRow, error) {
	return r.q.ListAPIKeysByProject(ctx, projectID)
}

func (r *pgAPIKeyRepo) GetByHash(ctx context.Context, keyHash string) (sqlc.ApiKey, error) {
	return r.q.GetAPIKeyByHash(ctx, keyHash)
}

func (r *pgAPIKeyRepo) Revoke(ctx context.Context, id, projectID pgtype.UUID) (sqlc.ApiKey, error) {
	return r.q.RevokeAPIKey(ctx, sqlc.RevokeAPIKeyParams{
		ID:        id,
		ProjectID: projectID,
	})
}
