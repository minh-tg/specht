package repo

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
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

// UpsertReportPackages persists the report's package inventory in one atomic
// statement. Duplicate PURLs within a report retain the first package's
// metadata, matching the former sequential conflict behavior.
func (r *pgInventoryRepo) UpsertReportPackages(ctx context.Context, reportID pgtype.UUID, packages []UpsertReportPackageParams) error {
	if len(packages) == 0 {
		return nil
	}
	return r.upsertPackages(ctx, r.query, reportID, packages)
}

type inventoryPackageRecord struct {
	PURL         string  `json:"purl"`
	Ecosystem    *string `json:"ecosystem"`
	Name         *string `json:"name"`
	Version      *string `json:"version"`
	ManifestPath *string `json:"manifest_path"`
}

func inventoryTextValue(value pgtype.Text) *string {
	if !value.Valid {
		return nil
	}
	return &value.String
}

// upsertPackages converts nullable package fields to JSON and sends one
// jsonb_to_recordset statement, avoiding a database round trip per package.
func (r *pgInventoryRepo) upsertPackages(ctx context.Context, q inventoryQueries, reportID pgtype.UUID, packages []UpsertReportPackageParams) error {
	rows := make([]inventoryPackageRecord, 0, len(packages))
	seen := make(map[string]struct{}, len(packages))
	for _, p := range packages {
		if _, exists := seen[p.PURL]; exists {
			continue
		}
		seen[p.PURL] = struct{}{}
		rows = append(rows, inventoryPackageRecord{
			PURL:         p.PURL,
			Ecosystem:    inventoryTextValue(p.Ecosystem),
			Name:         inventoryTextValue(p.Name),
			Version:      inventoryTextValue(p.Version),
			ManifestPath: inventoryTextValue(p.ManifestPath),
		})
	}
	if len(rows) == 0 {
		return nil
	}

	payload, err := json.Marshal(rows)
	if err != nil {
		return fmt.Errorf("encode report packages: %w", err)
	}
	if err := q.UpsertReportPackages(ctx, sqlc.UpsertReportPackagesParams{
		ReportID: reportID,
		Packages: payload,
	}); err != nil {
		return fmt.Errorf("upsert report packages: %w", err)
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
