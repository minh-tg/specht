package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

// StatsRepo serves aggregate project statistics.
type StatsRepo interface {
	GetProjectStats(ctx context.Context, projectID pgtype.UUID) ([]sqlc.GetProjectStatsRow, error)
	GetProjectWaiverCount(ctx context.Context, projectID pgtype.UUID) (int32, error)
	GetProjectReportCount(ctx context.Context, projectID pgtype.UUID) (int32, error)
	GetProjectLatestReport(ctx context.Context, projectID pgtype.UUID) (sqlc.GetProjectLatestReportRow, error)
	GetAgingRows(ctx context.Context, projectID pgtype.UUID) ([]sqlc.GetAgingRowsRow, error)
}

type pgStatsRepo struct {
	q *sqlc.Queries
}

func newStatsRepo(q *sqlc.Queries) *pgStatsRepo {
	return &pgStatsRepo{q: q}
}

func (r *pgStatsRepo) GetProjectStats(ctx context.Context, projectID pgtype.UUID) ([]sqlc.GetProjectStatsRow, error) {
	return r.q.GetProjectStats(ctx, projectID)
}

func (r *pgStatsRepo) GetProjectWaiverCount(ctx context.Context, projectID pgtype.UUID) (int32, error) {
	return r.q.GetProjectWaiverCount(ctx, projectID)
}

func (r *pgStatsRepo) GetProjectReportCount(ctx context.Context, projectID pgtype.UUID) (int32, error) {
	return r.q.GetProjectReportCount(ctx, projectID)
}

func (r *pgStatsRepo) GetProjectLatestReport(ctx context.Context, projectID pgtype.UUID) (sqlc.GetProjectLatestReportRow, error) {
	return r.q.GetProjectLatestReport(ctx, projectID)
}

func (r *pgStatsRepo) GetAgingRows(ctx context.Context, projectID pgtype.UUID) ([]sqlc.GetAgingRowsRow, error) {
	return r.q.GetAgingRows(ctx, projectID)
}
