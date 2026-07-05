package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

type pgArtifactRepo struct {
	q *sqlc.Queries
}

func (r *pgArtifactRepo) Upsert(ctx context.Context, arg sqlc.UpsertArtifactParams) (sqlc.Artifact, error) {
	return r.q.UpsertArtifact(ctx, arg)
}

func (r *pgArtifactRepo) List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Artifact, error) {
	return r.q.ListArtifacts(ctx, projectID)
}

func (r *pgArtifactRepo) ListByTarget(ctx context.Context, targetID pgtype.UUID) ([]sqlc.Artifact, error) {
	return r.q.ListArtifactsByTarget(ctx, targetID)
}

func (r *pgArtifactRepo) GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Artifact, error) {
	return r.q.GetArtifact(ctx, sqlc.GetArtifactParams{ID: id, ProjectID: projectID})
}

func (r *pgArtifactRepo) Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Artifact, error) {
	return r.q.DeleteArtifact(ctx, sqlc.DeleteArtifactParams{ID: id, ProjectID: projectID})
}
