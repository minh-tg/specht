package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

// CreateEvidenceParams is the input to creating an evidence artifact.
type CreateEvidenceParams struct {
	FindingID   pgtype.UUID
	Type        string
	URL         string
	Description string
	UploadedBy  pgtype.UUID
}

type pgEvidenceRepo struct {
	q *sqlc.Queries
}

func newEvidenceRepo(q *sqlc.Queries) *pgEvidenceRepo {
	return &pgEvidenceRepo{q: q}
}

func (r *pgEvidenceRepo) Create(ctx context.Context, arg CreateEvidenceParams) (sqlc.EvidenceArtifact, error) {
	return r.q.CreateEvidence(ctx, sqlc.CreateEvidenceParams{
		FindingID:   arg.FindingID,
		Type:        arg.Type,
		Url:         arg.URL,
		Description: arg.Description,
		UploadedBy:  arg.UploadedBy,
	})
}

func (r *pgEvidenceRepo) ListByFinding(ctx context.Context, findingID pgtype.UUID) ([]sqlc.EvidenceArtifact, error) {
	return r.q.ListEvidenceByFinding(ctx, findingID)
}

func (r *pgEvidenceRepo) GetByID(ctx context.Context, id pgtype.UUID) (sqlc.EvidenceArtifact, error) {
	return r.q.GetEvidenceByID(ctx, id)
}

func (r *pgEvidenceRepo) Delete(ctx context.Context, id pgtype.UUID) error {
	return r.q.DeleteEvidence(ctx, id)
}
