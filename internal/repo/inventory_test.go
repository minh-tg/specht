package repo

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockInventoryQueries struct {
	upsertReportPackagesFn func(ctx context.Context, arg sqlc.UpsertReportPackagesParams) error
	distinctInventoryFn    func(ctx context.Context, arg sqlc.DistinctInventoryParams) ([]sqlc.DistinctInventoryRow, error)
	deleteReportPackagesFn func(ctx context.Context, reportID pgtype.UUID) error
}

func (m *mockInventoryQueries) UpsertReportPackages(ctx context.Context, arg sqlc.UpsertReportPackagesParams) error {
	if m.upsertReportPackagesFn == nil {
		return errors.New("unexpected call to UpsertReportPackages")
	}
	return m.upsertReportPackagesFn(ctx, arg)
}

func (m *mockInventoryQueries) DistinctInventory(ctx context.Context, arg sqlc.DistinctInventoryParams) ([]sqlc.DistinctInventoryRow, error) {
	if m.distinctInventoryFn == nil {
		return nil, errors.New("unexpected call to DistinctInventory")
	}
	return m.distinctInventoryFn(ctx, arg)
}

func (m *mockInventoryQueries) DeleteReportPackages(ctx context.Context, reportID pgtype.UUID) error {
	if m.deleteReportPackagesFn == nil {
		return errors.New("unexpected call to DeleteReportPackages")
	}
	return m.deleteReportPackagesFn(ctx, reportID)
}

func testUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	var id pgtype.UUID
	require.NoError(t, id.Scan(s))
	return id
}

// TestInventoryRepo_UpsertReportPackages_BatchesRows verifies every unique
// package is encoded into one query, with nullable fields preserved and the
// first metadata row retained when a report repeats a PURL.
func TestInventoryRepo_UpsertReportPackages_BatchesRows(t *testing.T) {
	q := &mockInventoryQueries{}
	var got sqlc.UpsertReportPackagesParams
	calls := 0
	q.upsertReportPackagesFn = func(_ context.Context, arg sqlc.UpsertReportPackagesParams) error {
		calls++
		got = arg
		return nil
	}

	repo := &pgInventoryRepo{query: q}
	reportID := testUUID(t, "00000000-0000-0000-0000-0000000000ab")
	pkgs := []UpsertReportPackageParams{
		{
			PURL:         "pkg:npm/lodash@4.17.20",
			Ecosystem:    pgtype.Text{String: "npm", Valid: true},
			Name:         pgtype.Text{String: "lodash", Valid: true},
			Version:      pgtype.Text{String: "4.17.20", Valid: true},
			ManifestPath: pgtype.Text{String: "package-lock.json", Valid: true},
		},
		// The old sequential INSERT preserved the first row's metadata when a
		// duplicate PURL reached its ON CONFLICT path.
		{
			PURL:         "pkg:npm/lodash@4.17.20",
			Ecosystem:    pgtype.Text{String: "npm", Valid: true},
			Name:         pgtype.Text{String: "lodash", Valid: true},
			Version:      pgtype.Text{String: "4.17.20", Valid: true},
			ManifestPath: pgtype.Text{Valid: false},
		},
		{PURL: "pkg:golang/example.com/x@v1.0.0"},
	}

	err := repo.upsertPackages(context.Background(), q, reportID, pkgs)
	require.NoError(t, err)
	assert.Equal(t, 1, calls, "all packages must use one database query")
	assert.Equal(t, reportID, got.ReportID)

	var rows []inventoryPackageRecord
	require.NoError(t, json.Unmarshal(got.Packages, &rows))
	require.Len(t, rows, 2, "duplicate package URLs must collapse before the bulk upsert")
	assert.Equal(t, "pkg:npm/lodash@4.17.20", rows[0].PURL)
	assert.Equal(t, "npm", *rows[0].Ecosystem)
	assert.Equal(t, "package-lock.json", *rows[0].ManifestPath)
	assert.Equal(t, "pkg:golang/example.com/x@v1.0.0", rows[1].PURL)
	assert.Nil(t, rows[1].Ecosystem)
	assert.Nil(t, rows[1].ManifestPath)
}

func TestInventoryRepo_UpsertReportPackages_QueryFailure(t *testing.T) {
	q := &mockInventoryQueries{}
	calls := 0
	q.upsertReportPackagesFn = func(_ context.Context, _ sqlc.UpsertReportPackagesParams) error {
		calls++
		return errors.New("db unavailable")
	}
	repo := &pgInventoryRepo{query: q}

	err := repo.upsertPackages(context.Background(), q, testUUID(t, "00000000-0000-0000-0000-0000000000ab"), []UpsertReportPackageParams{
		{PURL: "pkg:npm/a@1.0.0"},
		{PURL: "pkg:npm/b@1.0.0"},
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "upsert report packages")
	assert.Equal(t, 1, calls, "the batch should execute one atomic query")
}

func TestInventoryRepo_DistinctInventory(t *testing.T) {
	q := &mockInventoryQueries{}
	var got sqlc.DistinctInventoryParams
	wantRows := []sqlc.DistinctInventoryRow{
		{
			ProjectID: testUUID(t, "00000000-0000-0000-0000-0000000000cd"),
			Purl:      "pkg:npm/lodash@4.17.20",
			Name:      pgtype.Text{String: "lodash", Valid: true},
		},
	}
	q.distinctInventoryFn = func(_ context.Context, arg sqlc.DistinctInventoryParams) ([]sqlc.DistinctInventoryRow, error) {
		got = arg
		return wantRows, nil
	}

	repo := &pgInventoryRepo{query: q}
	projectID := testUUID(t, "00000000-0000-0000-0000-0000000000cd")
	since := pgtype.Interval{Microseconds: 90 * 24 * int64(3600) * 1_000_000, Valid: true}

	rows, err := repo.DistinctInventory(context.Background(), projectID, since)
	require.NoError(t, err)
	assert.Equal(t, wantRows, rows)
	assert.Equal(t, projectID, got.ProjectID)
	assert.Equal(t, since, got.Since, "TTL interval must reach the query untouched")
}

func TestInventoryRepo_DeleteReportPackages(t *testing.T) {
	q := &mockInventoryQueries{}
	var got pgtype.UUID
	q.deleteReportPackagesFn = func(_ context.Context, reportID pgtype.UUID) error {
		got = reportID
		return nil
	}

	repo := &pgInventoryRepo{query: q}
	reportID := testUUID(t, "00000000-0000-0000-0000-0000000000ab")

	require.NoError(t, repo.DeleteReportPackages(context.Background(), reportID))
	assert.Equal(t, reportID, got)
}

func TestInventoryRepo_DeleteReportPackages_PropagatesError(t *testing.T) {
	q := &mockInventoryQueries{}
	q.deleteReportPackagesFn = func(_ context.Context, reportID pgtype.UUID) error {
		return errors.New("db unavailable")
	}

	repo := &pgInventoryRepo{query: q}
	err := repo.DeleteReportPackages(context.Background(), testUUID(t, "00000000-0000-0000-0000-0000000000ab"))
	require.Error(t, err)
}
