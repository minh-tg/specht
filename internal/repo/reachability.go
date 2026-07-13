package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

type UpsertReachabilityParams struct {
	FindingID  pgtype.UUID
	Reachable  bool
	Evidence   string
	AssessedBy pgtype.UUID
}

type pgReachabilityRepo struct {
	q *sqlc.Queries
}

func newReachabilityRepo(q *sqlc.Queries) *pgReachabilityRepo {
	return &pgReachabilityRepo{q: q}
}

func (r *pgReachabilityRepo) Upsert(ctx context.Context, arg UpsertReachabilityParams) (sqlc.ReachabilityAssessment, error) {
	return r.q.UpsertReachability(ctx, sqlc.UpsertReachabilityParams{
		FindingID:  arg.FindingID,
		Reachable:  arg.Reachable,
		Evidence:   arg.Evidence,
		AssessedBy: arg.AssessedBy,
	})
}

func (r *pgReachabilityRepo) ListByFinding(ctx context.Context, findingID pgtype.UUID) ([]sqlc.ReachabilityAssessment, error) {
	return r.q.ListReachabilityByFinding(ctx, findingID)
}

func (r *pgReachabilityRepo) GetByID(ctx context.Context, id pgtype.UUID) (sqlc.ReachabilityAssessment, error) {
	return r.q.GetReachability(ctx, id)
}
