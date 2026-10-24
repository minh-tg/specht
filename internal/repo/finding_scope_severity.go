package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// upsertInScope holds the finding's row lock from the upsert until the scope
// and aggregate severity are saved. Each statement sees the previous writer's
// committed scopes after waiting for its lock, rather than a prefetched maximum.
func (r *pgFindingRepo) upsertInScope(ctx context.Context, input UpsertFindingParams, scope port.FindingScopeSeverityInput) (sqlc.Finding, error) {
	reportID := pgtype.UUID{}
	var err error
	if scope.ReportID != "" {
		reportID, err = parseID(scope.ReportID)
		if err != nil {
			return sqlc.Finding{}, err
		}
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return sqlc.Finding{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	scoped := &pgFindingRepo{q: q}
	row, err := scoped.Upsert(ctx, input)
	if err != nil {
		return sqlc.Finding{}, err
	}
	if err := q.UpsertFindingScopeSeverity(ctx, sqlc.UpsertFindingScopeSeverityParams{
		FindingID: row.ID, ScopeHash: scope.ScopeHash,
		Severity: scope.Severity, SeverityRank: scope.SeverityRank,
		ReportID: reportID, ObservedAt: uuidFromTime(scope.ObservedAt),
	}); err != nil {
		return sqlc.Finding{}, err
	}
	row, err = q.RefreshFindingScopeSeverity(ctx, row.ID)
	if err != nil {
		return sqlc.Finding{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return sqlc.Finding{}, err
	}
	return row, nil
}

// retireAbsentScopeAndFix removes superseded scope values and refreshes their
// aggregate before closing findings. All scope writers lock the finding first.
func (r *pgFindingRepo) retireAbsentScopeAndFix(ctx context.Context, input sqlc.MarkAbsentScopedFindingsFixedParams) ([]sqlc.Finding, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)
	ids, err := q.LockAbsentScopeFindings(ctx, sqlc.LockAbsentScopeFindingsParams{
		ReportID: input.ReportID, ProjectID: input.ProjectID, ScopeHash: input.ScanScopeHash.String,
		FindingKinds: input.FindingKinds,
	})
	if err != nil {
		return nil, err
	}
	if len(ids) > 0 {
		if err := q.RetireAbsentScopeSeverities(ctx, sqlc.RetireAbsentScopeSeveritiesParams{
			FindingIds: ids, ScopeHash: input.ScanScopeHash.String, ReportID: input.ReportID,
		}); err != nil {
			return nil, err
		}
		if err := q.RefreshFindingScopeSeverities(ctx, ids); err != nil {
			return nil, err
		}
	}
	fixed, err := q.MarkAbsentScopedFindingsFixed(ctx, input)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return fixed, nil
}
