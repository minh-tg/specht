package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
)

// UpsertReachabilityParams is the input to a reachability-assessment upsert.
// State is one of the reachability_state values ('reachable',
// 'not_reachable', 'unknown', 'not_applicable').
type UpsertReachabilityParams struct {
	FindingID  pgtype.UUID
	State      string
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
		State:      sqlc.ReachabilityState(arg.State),
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

func (r *pgReachabilityRepo) LatestByFinding(ctx context.Context, findingID pgtype.UUID) (sqlc.ReachabilityAssessment, error) {
	return r.q.LatestReachabilityByFinding(ctx, findingID)
}

func (r *pgReachabilityRepo) LatestByFindings(ctx context.Context, findingIDs []pgtype.UUID) ([]sqlc.ReachabilityAssessment, error) {
	return r.q.LatestReachabilityByFindings(ctx, findingIDs)
}
