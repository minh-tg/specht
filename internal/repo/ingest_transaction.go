package repo

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

type pgIngestTransaction struct {
	pool   *pgxpool.Pool
	stores *port.Stores
}

func (r *pgIngestTransaction) Run(ctx context.Context, projectID string, fn func(*port.Stores) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := sqlc.New(tx)
	if err := q.LockProjectIngest(ctx, projectID); err != nil {
		return fmt.Errorf("lock project ingest: %w", err)
	}
	stores := *r.stores
	stores.Ingest = nil
	stores.Findings = newFindingPort(&pgFindingRepo{q: q, pool: tx})
	stores.Reports = newReportPort(&pgReportRepo{q: q, pool: tx})
	stores.Inventory = &pgInventoryPort{inner: &pgInventoryRepo{query: q}}
	if err := fn(&stores); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
