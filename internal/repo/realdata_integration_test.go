//go:build integration

// DB-backed validation: the same scan ingested twice (distinct raw
// bytes, identical findings) must not duplicate finding rows, must record a
// second report, and must leave finding states untouched. Ingest has no
// auto-close path — states only move through triage — and this pins that.
package repo

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"

	"github.com/xMinhx/specht/internal/db"
	"github.com/xMinhx/specht/internal/parser"
	"github.com/xMinhx/specht/internal/scanner"
	"github.com/xMinhx/specht/internal/usecase"
)

func setupIngestPool(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:17-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "specht",
			"POSTGRES_PASSWORD": "specht",
			"POSTGRES_DB":       "specht_test",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)
	mappedPort, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := "postgres://specht:specht@" + host + ":" + mappedPort.Port() + "/specht_test?sslmode=disable"
	require.NoError(t, db.RunMigrations(dsn, "../../migrations"))

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)

	return pool, func() {
		pool.Close()
		_ = container.Terminate(ctx)
	}
}

func TestRealDataDoubleIngest_Idempotent(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()

	stores := NewPortStores(pool)
	reg := scanner.NewRegistry()
	for _, s := range parser.Builtins() {
		require.NoError(t, reg.Register(s))
	}
	uc := usecase.New(usecase.Deps{Stores: stores, Registry: reg})

	_, err := uc.CreateProject(ctx, "My App", "my-app", "validation")
	require.NoError(t, err)

	raw1, err := os.ReadFile("../parser/trivy/testdata/multi-type-scan.json")
	require.NoError(t, err)
	// Distinct raw bytes (new report row) with identical findings.
	raw2 := append(append([]byte{}, raw1...), '\n')

	out1, err := uc.IngestReport(ctx, usecase.IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: raw1,
	})
	require.NoError(t, err)
	require.Equal(t, 4, out1.TotalFindings)

	out2, err := uc.IngestReport(ctx, usecase.IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: raw2,
	})
	require.NoError(t, err)
	require.Equal(t, 4, out2.TotalFindings)
	require.NotEqual(t, out1.ReportID, out2.ReportID, "distinct raw bytes must record distinct reports")

	project, err := stores.Projects.GetBySlug(ctx, "my-app")
	require.NoError(t, err)
	findings, err := stores.Findings.ListByProject(ctx, project.ID, nil, nil, nil, 100, 0)
	require.NoError(t, err)
	require.Len(t, findings, 4, "re-ingest must not duplicate finding rows")
	for _, f := range findings {
		assert.Equal(t, "open", f.State, "ingest must never move finding state")
	}
}
