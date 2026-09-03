package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

// UpsertSignoffParams is the input to a signoff upsert.
type UpsertSignoffParams struct {
	FindingID  pgtype.UUID
	Status     string
	ReviewedBy pgtype.UUID
	Comment    string
}

type pgSignoffRepo struct {
	q *sqlc.Queries
}

func newSignoffRepo(q *sqlc.Queries) *pgSignoffRepo {
	return &pgSignoffRepo{q: q}
}

func (r *pgSignoffRepo) Upsert(ctx context.Context, arg UpsertSignoffParams) (sqlc.Signoff, error) {
	return r.q.UpsertSignoff(ctx, sqlc.UpsertSignoffParams{
		FindingID:  arg.FindingID,
		Status:     sqlc.SignoffStatus(arg.Status),
		ReviewedBy: arg.ReviewedBy,
		Comment:    arg.Comment,
	})
}

func (r *pgSignoffRepo) GetByFinding(ctx context.Context, findingID pgtype.UUID) (sqlc.Signoff, error) {
	return r.q.GetSignoffByFinding(ctx, findingID)
}
