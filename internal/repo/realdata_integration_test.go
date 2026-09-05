//go:build integration

// DB-backed validation: the same scan ingested twice (distinct raw
// bytes, identical findings) must not duplicate finding rows, must record a
// second report, and must leave finding states untouched. Ingest has no
// auto-close path — states only move through triage — and this pins that.
package repo

import (
	"context"
	"encoding/json"
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

func strPtr(s string) *string { return &s }

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

func TestArtifactDigestDedup(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()

	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "my-app", Name: "My App",
		DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)

	upsert := func(digest *string) port.Artifact {
		t.Helper()
		a, err := stores.Artifacts.Upsert(ctx, port.ArtifactInput{
			ProjectID: project.ID, ArtifactType: "container_image",
			Name: "myapp", Version: strPtr("1.2.3"), Digest: digest,
			Metadata: json.RawMessage("{}"),
		})
		require.NoError(t, err)
		return a
	}

	first := upsert(strPtr("sha256:aaa"))
	again := upsert(strPtr("sha256:aaa"))
	assert.Equal(t, first.ID, again.ID, "same digest upserts the same row")
	second := upsert(strPtr("sha256:bbb"))
	assert.NotEqual(t, first.ID, second.ID, "rebuild under one tag is a distinct artifact")

	all, err := stores.Artifacts.List(ctx, project.ID)
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestNucleiIngest_EndToEnd(t *testing.T) {
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

	raw, err := os.ReadFile("../parser/nuclei/testdata/nuclei.jsonl")
	require.NoError(t, err)
	out, err := uc.IngestReport(ctx, usecase.IngestReportInput{
		ProjectSlug: "my-app", Scanner: "nuclei", RawData: raw,
		Environment: "staging",
	})
	require.NoError(t, err)
	require.Equal(t, 3, out.TotalFindings)
	project, err := stores.Projects.GetBySlug(ctx, "my-app")
	require.NoError(t, err)
	findings, err := stores.Findings.ListByProject(ctx, project.ID, nil, nil, []string{"dast"}, nil, nil, 100, 0)
	require.NoError(t, err)
	require.Len(t, findings, 2, "dast kind must satisfy the finding_kinds FK and dast scan_type the reports CHECK; two events share one identity")
	for _, f := range findings {
		assert.Equal(t, "dast", f.FindingKind)
	}
	stored, err := stores.Reports.ListByProject(ctx, project.ID, 10, 0)
	require.NoError(t, err)
	require.Len(t, stored, 1)
	assert.Equal(t, "dast", stored[0].ScanType)
}

func TestRemediation_EndToEnd(t *testing.T) {
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

	raw, err := os.ReadFile("../parser/checkov/testdata/checkov-terraform.json")
	require.NoError(t, err)
	out, err := uc.IngestReport(ctx, usecase.IngestReportInput{
		ProjectSlug: "my-app", Scanner: "checkov", RawData: raw,
	})
	require.NoError(t, err)
	require.Equal(t, 3, out.TotalFindings)

	project, err := stores.Projects.GetBySlug(ctx, "my-app")
	require.NoError(t, err)
	findings, err := stores.Findings.ListByProject(ctx, project.ID, nil, nil, []string{"iac"}, nil, nil, 100, 0)
	require.NoError(t, err)
	require.Len(t, findings, 3)

	detail, err := uc.GetFinding(ctx, findings[0].ID)
	require.NoError(t, err)
	require.NotNil(t, detail.Remediation, "guideline-backed fix must surface on detail")
	assert.False(t, detail.Remediation.Fallback)
	assert.Contains(t, detail.Remediation.URL, "bridgecrew.io")
	assert.Equal(t, "checkov", detail.Remediation.Source)
	require.NotNil(t, detail.Location)
	assert.NotEmpty(t, detail.Location.Resource)
	assert.NotEmpty(t, detail.Location.File)
}

func TestSuggestion_EndToEnd(t *testing.T) {
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

	raw, err := os.ReadFile("../parser/trivy/testdata/multi-type-scan.json")
	require.NoError(t, err)
	out, err := uc.IngestReport(ctx, usecase.IngestReportInput{
		ProjectSlug: "my-app", Scanner: "trivy", RawData: raw,
	})
	require.NoError(t, err)
	require.Equal(t, 4, out.TotalFindings)

	project, err := stores.Projects.GetBySlug(ctx, "my-app")
	require.NoError(t, err)
	findings, err := stores.Findings.ListByProject(ctx, project.ID, nil, nil, []string{"sca"}, nil, nil, 100, 0)
	require.NoError(t, err)
	require.NotEmpty(t, findings)

	var upgraded bool
	for _, f := range findings {
		detail, err := uc.GetFinding(ctx, f.ID)
		require.NoError(t, err)
		require.NotNil(t, detail.Suggestion)
		if detail.Suggestion.Confidence == "high" {
			upgraded = true
			assert.Equal(t, "upgrade", detail.Suggestion.Action)
			assert.NotEmpty(t, detail.Suggestion.Target)
		}
	}
	assert.True(t, upgraded, "the curl CVE carries a fixed version and must yield a high upgrade suggestion")
}
