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
