package repo

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minh-tg/specht/internal/db/sqlc"
)

// inventoryQueries is the subset of sqlc.Queries the inventory repo uses. It
// exists so the repo logic can be unit tested against a mock instead of a live
// database; *sqlc.Queries satisfies it.
type inventoryQueries interface {
	UpsertReportPackages(ctx context.Context, arg sqlc.UpsertReportPackagesParams) error
	DistinctInventory(ctx context.Context, arg sqlc.DistinctInventoryParams) ([]sqlc.DistinctInventoryRow, error)
	DeleteReportPackages(ctx context.Context, reportID pgtype.UUID) error
}

type pgInventoryRepo struct {
	query inventoryQueries
	pool  *pgxpool.Pool
}

// UpsertReportPackageParams identifies one inventory row to persist for a
// report. PURLs are already normalized by the parsers.
type UpsertReportPackageParams struct {
	PURL         string
	Ecosystem    pgtype.Text
	Name         pgtype.Text
	Version      pgtype.Text
	ManifestPath pgtype.Text
}

// UpsertReportPackages persists the report's package inventory atomically: all
// rows are written in a single transaction, and a repeated (report_id, purl)
// updates last_seen_at (server-side NOW()) instead of duplicating. Any failure
// rolls back the whole batch.
func (r *pgInventoryRepo) UpsertReportPackages(ctx context.Context, reportID pgtype.UUID, packages []UpsertReportPackageParams) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	if err := r.upsertPackages(ctx, sqlc.New(tx), reportID, packages); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// upsertPackages is the per-row write loop, kept separate from the transaction
// plumbing so it can be exercised against a mocked queries interface.
func (r *pgInventoryRepo) upsertPackages(ctx context.Context, q inventoryQueries, reportID pgtype.UUID, packages []UpsertReportPackageParams) error {
	for _, p := range packages {
		err := q.UpsertReportPackages(ctx, sqlc.UpsertReportPackagesParams{
			ReportID:     reportID,
			Purl:         p.PURL,
			Ecosystem:    p.Ecosystem,
			Name:         p.Name,
			Version:      p.Version,
			ManifestPath: p.ManifestPath,
		})
		if err != nil {
			return fmt.Errorf("upsert report package %q: %w", p.PURL, err)
		}
	}
	return nil
}

// DistinctInventory returns the distinct packages a project has seen within the
// given TTL window (last_seen_at >= now() - since).
func (r *pgInventoryRepo) DistinctInventory(ctx context.Context, projectID pgtype.UUID, since pgtype.Interval) ([]sqlc.DistinctInventoryRow, error) {
	return r.query.DistinctInventory(ctx, sqlc.DistinctInventoryParams{
		ProjectID: projectID,
		Since:     since,
	})
}

// DeleteReportPackages removes every package row for a report. The foreign key
// already cascades on report delete; this is the explicit cleanup path.
func (r *pgInventoryRepo) DeleteReportPackages(ctx context.Context, reportID pgtype.UUID) error {
	return r.query.DeleteReportPackages(ctx, reportID)
}
