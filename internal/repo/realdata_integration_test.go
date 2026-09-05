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
	"github.com/xMinhx/specht/internal/port"
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
	findings, err := stores.Findings.ListByProject(ctx, project.ID, nil, nil, nil, nil, nil, 100, 0)
	require.NoError(t, err)
	require.Len(t, findings, 4, "re-ingest must not duplicate finding rows")
	for _, f := range findings {
		assert.Equal(t, "open", f.State, "ingest must never move finding state")
	}
}

func TestRealDataContext_EndToEnd(t *testing.T) {
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

	ingest := func(raw []byte, branch, commit, owner string) {
		t.Helper()
		_, err := uc.IngestReport(ctx, usecase.IngestReportInput{
			ProjectSlug: "my-app", Scanner: "trivy", RawData: raw,
			Branch: branch, CommitSha: commit,
			Environment: "production", Owner: owner,
		})
		require.NoError(t, err)
	}
	targetOwner := func() string {
		t.Helper()
		targets, err := stores.Targets.List(ctx, mustProjectID(t, ctx, stores))
		require.NoError(t, err)
		require.Len(t, targets, 1)
		if targets[0].Owner == nil {
			return ""
		}
		return *targets[0].Owner
	}

	ingest(raw1, "main", "aaa", "team-a")
	require.Equal(t, "team-a", targetOwner())

	// Same findings on another branch with no owner: rows must not fork
	// and the stored owner must be preserved, not cleared.
	raw2 := append(append([]byte{}, raw1...), '\n')
	ingest(raw2, "feature", "bbb", "")
	require.Equal(t, "team-a", targetOwner(), "absent owner must preserve the stored value")

	// A supplied owner overwrites (last supplied wins).
	raw3 := append(append([]byte{}, raw1...), '\n', '\n')
	ingest(raw3, "feature", "ccc", "team-b")
	require.Equal(t, "team-b", targetOwner())

	project, err := stores.Projects.GetBySlug(ctx, "my-app")
	require.NoError(t, err)
	findings, err := stores.Findings.ListByProject(ctx, project.ID, nil, nil, nil, nil, nil, 100, 0)
	require.NoError(t, err)
	require.Len(t, findings, 4, "context changes must not fork finding rows")

	// Detail exposes the latest observed context.
	detail, err := uc.GetFinding(ctx, findings[0].ID)
	require.NoError(t, err)
	require.NotNil(t, detail.Context)
	assert.NotEmpty(t, detail.Context.TargetName)
	assert.Equal(t, "production", detail.Context.EnvironmentName)
	assert.Equal(t, "feature", detail.Context.Branch)
	assert.Equal(t, "ccc", detail.Context.CommitSha)
	assert.Equal(t, "team-b", detail.Context.TargetOwner)

	// Name filters match against linked observations.
	targets, err := stores.Targets.List(ctx, project.ID)
	require.NoError(t, err)
	prod, err := stores.Findings.ListByProject(ctx, project.ID, nil, nil, nil, []string{"production"}, nil, 100, 0)
	require.NoError(t, err)
	assert.Len(t, prod, 4)
	staging, err := stores.Findings.ListByProject(ctx, project.ID, nil, nil, nil, []string{"staging"}, nil, 100, 0)
	require.NoError(t, err)
	assert.Empty(t, staging)
	byTarget, err := stores.Findings.ListByProject(ctx, project.ID, nil, nil, nil, nil, []string{targets[0].Name}, 100, 0)
	require.NoError(t, err)
	assert.Len(t, byTarget, 4)
	byMissing, err := stores.Findings.ListByProject(ctx, project.ID, nil, nil, nil, nil, []string{"does-not-exist"}, 100, 0)
	require.NoError(t, err)
	assert.Empty(t, byMissing)
}

func mustProjectID(t *testing.T, ctx context.Context, stores *port.Stores) string {
	t.Helper()
	project, err := stores.Projects.GetBySlug(ctx, "my-app")
	require.NoError(t, err)
	return project.ID
}

func TestAgingRows_EndToEnd(t *testing.T) {
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
	project, err := stores.Projects.GetBySlug(ctx, "my-app")
	require.NoError(t, err)

	now := time.Now().UTC()
	seed := func(fp string, rank int16, daysAgo int) string {
		t.Helper()
		ts := now.AddDate(0, 0, -daysAgo)
		f, err := stores.Findings.Upsert(ctx, project.ID, "sca", fp, fp, "critical", rank, 9.0, ts, now)
		require.NoError(t, err)
		return f.ID
	}

	oldCritical := seed("fp-old-critical", 4, 40)
	oldLow := seed("fp-old-low", 1, 100)
	_, err = stores.Findings.CreateEvent(ctx, port.FindingEventInput{
		FindingID: oldCritical, EventType: "reopened_severity_change",
	})
	require.NoError(t, err)

	rows, err := stores.Stats.GetAgingRows(ctx, project.ID)
	require.NoError(t, err)
	require.Len(t, rows, 2)
	byID := map[string]port.AgingRow{}
	for _, r := range rows {
		byID[r.ID] = r
	}
	assert.True(t, byID[oldCritical].Reopened)
	assert.False(t, byID[oldLow].Reopened)
	assert.Equal(t, "critical", byID[oldCritical].Severity)

	resp, err := uc.GetAging(ctx, "my-app")
	require.NoError(t, err)
	assert.Equal(t, int32(1), resp.OverdueTotal, "40d critical past 7d SLA; 100d low within 180d SLA")
	assert.Equal(t, int32(1), resp.Reopened)
}
