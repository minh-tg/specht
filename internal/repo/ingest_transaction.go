package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

type pgIngestTransaction struct {
	pool   *pgxpool.Pool
	stores *port.Stores
}

func (r *pgIngestTransaction) Run(ctx context.Context, projectID, keyHash string, fn func(*port.Stores) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	q := sqlc.New(tx)
	if err := q.LockProjectIngest(ctx, projectID); err != nil {
		return fmt.Errorf("lock project ingest: %w", err)
	}
	if keyHash != "" {
		if err := lockIngestKey(ctx, q, keyHash); err != nil {
			return err
		}
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

// lockIngestKey holds the key and its creator's account row for the rest of
// the transaction and fails with port.ErrAPIKeyInactive when the key is revoked
// or the creator deactivated. The creator is locked before the key, the order a
// deactivation updates them in, so the two cannot wait on each other. A
// deactivation that comes later waits for this transaction and then revokes the
// key; one that came earlier is seen here.
func lockIngestKey(ctx context.Context, q *sqlc.Queries, keyHash string) error {
	creator, err := q.GetLiveAPIKeyCreator(ctx, keyHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return port.ErrAPIKeyInactive
	} else if err != nil {
		return err
	}
	if creator.Valid {
		if _, err := q.LockKeyCreator(ctx, creator); errors.Is(err, pgx.ErrNoRows) {
			return port.ErrAPIKeyInactive
		} else if err != nil {
			return err
		}
	}
	if _, err := q.LockLiveAPIKey(ctx, keyHash); errors.Is(err, pgx.ErrNoRows) {
		return port.ErrAPIKeyInactive
	} else if err != nil {
		return err
	}
	return nil
}
