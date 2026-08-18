package repo

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/db/sqlc"
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

// TestInventoryRepo_UpsertReportPackages_PassesParams verifies every input
// package becomes one query call carrying the report id and normalized fields,
// in order, with no client-supplied timestamps (bumping lives in SQL: NOW()).
func TestInventoryRepo_UpsertReportPackages_PassesParams(t *testing.T) {
	q := &mockInventoryQueries{}
	var got []sqlc.UpsertReportPackagesParams
	q.upsertReportPackagesFn = func(_ context.Context, arg sqlc.UpsertReportPackagesParams) error {
		got = append(got, arg)
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
		// Duplicate PURL within one report: the repo must forward it — the
		// (report_id, purl) primary key is what collapses it, not the repo.
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
	require.Len(t, got, len(pkgs))
	for i, want := range pkgs {
		assert.Equal(t, reportID, got[i].ReportID)
		assert.Equal(t, want.PURL, got[i].Purl)
		assert.Equal(t, want.Ecosystem, got[i].Ecosystem)
		assert.Equal(t, want.Name, got[i].Name)
		assert.Equal(t, want.Version, got[i].Version)
		assert.Equal(t, want.ManifestPath, got[i].ManifestPath)
	}
}

// TestInventoryRepo_UpsertReportPackages_FailureAbortsBatch verifies a failing
// row stops the batch (the transaction wrapper will then roll everything back).
func TestInventoryRepo_UpsertReportPackages_FailureAbortsBatch(t *testing.T) {
	q := &mockInventoryQueries{}
	calls := 0
	q.upsertReportPackagesFn = func(_ context.Context, arg sqlc.UpsertReportPackagesParams) error {
		calls++
		if calls == 2 {
			return errors.New("db unavailable")
		}
		return nil
	}

	repo := &pgInventoryRepo{query: q}
	pkgs := []UpsertReportPackageParams{
		{PURL: "pkg:npm/a@1.0.0"},
		{PURL: "pkg:npm/b@1.0.0"},
		{PURL: "pkg:npm/c@1.0.0"},
	}

	err := repo.upsertPackages(context.Background(), q, testUUID(t, "00000000-0000-0000-0000-0000000000ab"), pkgs)
	require.Error(t, err)
	assert.ErrorContains(t, err, "pkg:npm/b@1.0.0")
	assert.Equal(t, 2, calls, "batch must stop at the first failing row")
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
