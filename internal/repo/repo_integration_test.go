//go:build integration

package repo

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/xMinhx/specht/internal/db"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

func setupTestDB(t *testing.T) (*Repos, func()) {
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
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := fmt.Sprintf("postgres://specht:specht@%s:%s/specht_test?sslmode=disable", host, port.Port())

	err = db.RunMigrations(dsn, "../../migrations")
	require.NoError(t, err, "migrations must apply")

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)

	repos := NewRepos(pool)

	cleanup := func() {
		pool.Close()
		container.Terminate(ctx)
	}

	return repos, cleanup
}

func TestProjectRepo_GetBySlug_NotFound(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := repos.Projects.GetBySlug(context.Background(), "test-project")
	assert.Error(t, err)
}

func TestUserRepo_CreateAndGetByEmail(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	user, err := repos.Users.Create(
		context.Background(), "alice@test.com",
		pgtype.Text{Valid: false},
		pgtype.Text{String: "$2a$10$hash", Valid: true},
	)
	require.NoError(t, err)
	assert.Equal(t, "alice@test.com", user.Email)
	assert.True(t, user.ID.Valid)

	fetched, err := repos.Users.GetByEmail(context.Background(), "alice@test.com")
	require.NoError(t, err)
	assert.Equal(t, user.ID.Bytes, fetched.ID.Bytes)

	fetchedByID, err := repos.Users.GetByID(context.Background(), user.ID)
	require.NoError(t, err)
	assert.Equal(t, user.Email, fetchedByID.Email)
}

func TestUserRepo_GetByEmail_NotFound(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := repos.Users.GetByEmail(context.Background(), "nonexistent@test.com")
	assert.Error(t, err)
}

func TestProjectRepo_CreateAndList(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := repos.Projects.Create(context.Background(), sqlc.CreateProjectParams{
		Slug:                "proj-a",
		Name:                "Project A",
		Description:         pgtype.Text{Valid: false},
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	require.NoError(t, err)

	_, err = repos.Projects.Create(context.Background(), sqlc.CreateProjectParams{
		Slug:                "proj-b",
		Name:                "Project B",
		Description:         pgtype.Text{Valid: false},
		DeploymentThreshold: "medium",
		Settings:            []byte("{}"),
	})
	require.NoError(t, err)

	projects, err := repos.Projects.List(context.Background())
	require.NoError(t, err)
	assert.Len(t, projects, 2)
}

func TestProjectRepo_GetBySlug(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	_, err := repos.Projects.Create(context.Background(), sqlc.CreateProjectParams{
		Slug:                "my-app",
		Name:                "My App",
		Description:         pgtype.Text{Valid: false},
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	require.NoError(t, err)

	fetched, err := repos.Projects.GetBySlug(context.Background(), "my-app")
	require.NoError(t, err)
	assert.Equal(t, "my-app", fetched.Slug)
	assert.Equal(t, "My App", fetched.Name)

	_, err = repos.Projects.GetBySlug(context.Background(), "nonexistent")
	assert.Error(t, err)
}

func TestReportRepo_CreateAndGetByID(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	project, err := repos.Projects.Create(context.Background(), sqlc.CreateProjectParams{
		Slug:                "my-app",
		Name:                "My App",
		Description:         pgtype.Text{Valid: false},
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	require.NoError(t, err)

	report, err := repos.Reports.Create(context.Background(), CreateReportParams{
		ProjectID:     project.ID,
		ToolName:      "trivy",
		ToolVersion:   pgtype.Text{Valid: false},
		ScanType:      "image",
		ScanTarget:    pgtype.Text{String: "myapp:latest", Valid: true},
		ScanScope:     []byte(`{}`),
		Branch:        pgtype.Text{Valid: false},
		CommitSha:     pgtype.Text{Valid: false},
		RawReportHash: pgtype.Text{Valid: false},
		ParserVersion: pgtype.Text{Valid: false},
	})
	require.NoError(t, err)
	assert.True(t, report.ID.Valid)
	assert.Equal(t, "processing", report.Status)

	fetched, err := repos.Reports.GetByID(context.Background(), report.ID)
	require.NoError(t, err)
	assert.Equal(t, report.ID.Bytes, fetched.ID.Bytes)

	_, err = repos.Reports.UpdateStatus(context.Background(), report.ID, project.ID, "completed", 5, pgtype.Text{Valid: false})
	require.NoError(t, err)

	updated, err := repos.Reports.GetByID(context.Background(), report.ID)
	require.NoError(t, err)
	assert.Equal(t, "completed", updated.Status)
	assert.True(t, updated.CompletedAt.Valid)
}

func TestReportRepo_ListByProject(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	project, err := repos.Projects.Create(context.Background(), sqlc.CreateProjectParams{
		Slug:                "my-app",
		Name:                "My App",
		Description:         pgtype.Text{Valid: false},
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	require.NoError(t, err)

	for i := 0; i < 3; i++ {
		_, err := repos.Reports.Create(context.Background(), CreateReportParams{
			ProjectID:     project.ID,
			ToolName:      "trivy",
			ToolVersion:   pgtype.Text{Valid: false},
			ScanType:      "image",
			ScanTarget:    pgtype.Text{Valid: false},
			ScanScope:     []byte(`{}`),
			Branch:        pgtype.Text{Valid: false},
			CommitSha:     pgtype.Text{Valid: false},
			RawReportHash: pgtype.Text{Valid: false},
			ParserVersion: pgtype.Text{Valid: false},
		})
		require.NoError(t, err)
	}

	reports, err := repos.Reports.ListByProject(context.Background(), project.ID, 10, 0)
	require.NoError(t, err)
	assert.Len(t, reports, 3)

	reportsPage2, err := repos.Reports.ListByProject(context.Background(), project.ID, 2, 0)
	require.NoError(t, err)
	assert.Len(t, reportsPage2, 2)
}

func TestFindingRepo_UpsertAndList(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	project, err := repos.Projects.Create(context.Background(), sqlc.CreateProjectParams{
		Slug:                "my-app",
		Name:                "My App",
		Description:         pgtype.Text{Valid: false},
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	require.NoError(t, err)

	report, err := repos.Reports.Create(context.Background(), CreateReportParams{
		ProjectID:     project.ID,
		ToolName:      "trivy",
		ToolVersion:   pgtype.Text{Valid: false},
		ScanType:      "image",
		ScanTarget:    pgtype.Text{Valid: false},
		ScanScope:     []byte(`{}`),
		Branch:        pgtype.Text{Valid: false},
		CommitSha:     pgtype.Text{Valid: false},
		RawReportHash: pgtype.Text{Valid: false},
		ParserVersion: pgtype.Text{Valid: false},
	})
	require.NoError(t, err)

	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	finding, err := repos.Findings.Upsert(context.Background(), UpsertFindingParams{
		ProjectID:    project.ID,
		FindingKind:  "sca",
		Fingerprint:  "pkg:npm/lodash@4.17.20",
		CurrentTitle: "CVE-2026-1234",
		Severity:     "high",
		SeverityRank: 3,
		Score:        pgtype.Numeric{Valid: false},
		FirstSeenAt:  now,
		LastSeenAt:   now,
	})
	require.NoError(t, err)
	assert.True(t, finding.ID.Valid)
	assert.Equal(t, "open", finding.State)

	occ, err := repos.Findings.CreateOccurrence(context.Background(), CreateOccurrenceParams{
		FindingID:       finding.ID,
		ReportID:        report.ID,
		Title:           "CVE-2026-1234 in lodash",
		Description:     pgtype.Text{Valid: false},
		Severity:        "high",
		SeverityRank:    3,
		Score:           pgtype.Numeric{Valid: false},
		ToolName:        "trivy",
		ToolVersion:     pgtype.Text{Valid: false},
		ParserVersion:   pgtype.Text{Valid: false},
		LocationSummary: pgtype.Text{String: "package-lock.json", Valid: true},
		Display:         []byte(`{}`),
		Metadata:        []byte(`{}`),
	})
	require.NoError(t, err)
	assert.True(t, occ.ID.Valid)

	dim, err := repos.Findings.UpsertDimension(context.Background(), UpsertDimensionParams{
		FindingID: finding.ID,
		Key:       "component.purl",
		Value:     "pkg:npm/lodash@4.17.20",
		Source:    pgtype.Text{String: "trivy", Valid: true},
	})
	require.NoError(t, err)
	assert.True(t, dim.ID.Valid)

	upsertedAgain, err := repos.Findings.Upsert(context.Background(), UpsertFindingParams{
		ProjectID:    project.ID,
		FindingKind:  "sca",
		Fingerprint:  "pkg:npm/lodash@4.17.20",
		CurrentTitle: "CVE-2026-1234 (updated)",
		Severity:     "critical",
		SeverityRank: 4,
		Score:        pgtype.Numeric{Valid: false},
		FirstSeenAt:  now,
		LastSeenAt:   now,
	})
	require.NoError(t, err)
	assert.Equal(t, "open", upsertedAgain.State)
	assert.Equal(t, "CVE-2026-1234 (updated)", upsertedAgain.CurrentTitle)

	findings, err := repos.Findings.ListByProject(context.Background(), project.ID, nil, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, findings, 1)

	criticalFindings, err := repos.Findings.ListByProject(context.Background(), project.ID, []string{"critical"}, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, criticalFindings, 1)

	lowFindings, err := repos.Findings.ListByProject(context.Background(), project.ID, []string{"low"}, nil, 10, 0)
	require.NoError(t, err)
	assert.Len(t, lowFindings, 0)
}

func TestAPIKeyRepo_CreateAndRevoke(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	project, err := repos.Projects.Create(context.Background(), sqlc.CreateProjectParams{
		Slug:                "my-app",
		Name:                "My App",
		Description:         pgtype.Text{Valid: false},
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	require.NoError(t, err)

	key, err := repos.APIKeys.Create(context.Background(), sqlc.CreateAPIKeyParams{
		ProjectID: project.ID,
		Name:      "ci-key",
		KeyPrefix: "vuln_abc",
		KeyHash:   "abc123hash",
		LastFour:  pgtype.Text{String: "1234", Valid: true},
		Scopes:    []byte(`["ingest"]`),
	})
	require.NoError(t, err)
	assert.True(t, key.ID.Valid)
	assert.False(t, key.RevokedAt.Valid)

	keys, err := repos.APIKeys.ListByProject(context.Background(), project.ID)
	require.NoError(t, err)
	assert.Len(t, keys, 1)

	fetched, err := repos.APIKeys.GetByHash(context.Background(), "abc123hash")
	require.NoError(t, err)
	assert.Equal(t, "ci-key", fetched.Name)

	revoked, err := repos.APIKeys.Revoke(context.Background(), key.ID, project.ID)
	require.NoError(t, err)
	assert.True(t, revoked.RevokedAt.Valid)

	keysAfterRevoke, err := repos.APIKeys.ListByProject(context.Background(), project.ID)
	require.NoError(t, err)
	assert.Len(t, keysAfterRevoke, 0)
}

func createTestProject(t *testing.T, repos *Repos) sqlc.Project {
	t.Helper()
	project, err := repos.Projects.Create(context.Background(), sqlc.CreateProjectParams{
		Slug:                "test-" + uuid.New().String()[:8],
		Name:                "Test Project",
		Description:         pgtype.Text{Valid: false},
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	require.NoError(t, err)
	return project
}

func TestWaiverTableRoundTrip(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	project := createTestProject(t, repos)

	w, err := repos.Waivers.Create(context.Background(), sqlc.CreateWaiverParams{
		ProjectID:   project.ID,
		Name:        "test-waiver",
		Description: "A test waiver",
		Enabled:     true,
	})
	require.NoError(t, err)
	assert.True(t, w.ID.Valid)
	assert.Equal(t, "test-waiver", w.Name)
	assert.True(t, w.Enabled)
	assert.True(t, w.CreatedAt.Valid)
	assert.True(t, w.UpdatedAt.Valid)

	cond, err := repos.Waivers.CreateCondition(context.Background(), sqlc.CreateWaiverConditionParams{
		WaiverID: w.ID,
		Field:    "severity_rank",
		Operator: "gte",
		Value:    "4",
	})
	require.NoError(t, err)
	assert.Equal(t, "severity_rank", cond.Field)
	assert.Equal(t, "gte", cond.Operator)
	assert.Equal(t, "4", cond.Value)

	ctx, err := repos.Waivers.CreateContext(context.Background(), sqlc.CreateWaiverContextParams{
		WaiverID:      w.ID,
		EnvironmentID: pgtype.UUID{Valid: false},
		TargetID:      pgtype.UUID{Valid: false},
		ArtifactID:    pgtype.UUID{Valid: false},
	})
	require.NoError(t, err)
	assert.True(t, ctx.ID.Valid)

	finding, err := repos.Findings.Upsert(context.Background(), UpsertFindingParams{
		ProjectID:    project.ID,
		FindingKind:  "sca",
		Fingerprint:  "pkg:npm/test@1.0.0",
		CurrentTitle: "Test finding",
		Severity:     "high",
		SeverityRank: 3,
		Score:        pgtype.Numeric{Valid: false},
		FirstSeenAt:  pgtype.Timestamptz{Time: time.Now(), Valid: true},
		LastSeenAt:   pgtype.Timestamptz{Time: time.Now(), Valid: true},
	})
	require.NoError(t, err)

	target, err := repos.Waivers.CreateFindingTarget(context.Background(), sqlc.CreateWaiverFindingTargetParams{
		WaiverID:  w.ID,
		FindingID: finding.ID,
	})
	require.NoError(t, err)
	assert.True(t, target.ID.Valid)

	ev, err := repos.Waivers.CreateEvent(context.Background(), sqlc.CreateWaiverEventParams{
		WaiverID:  w.ID,
		EventType: "created",
		ActorID:   pgtype.Text{String: "user-abc", Valid: true},
		Metadata:  []byte(`{}`),
	})
	require.NoError(t, err)
	assert.Equal(t, "created", ev.EventType)
	assert.Equal(t, "user-abc", ev.ActorID.String)

	fetched, err := repos.Waivers.GetByID(context.Background(), w.ID, project.ID)
	require.NoError(t, err)
	assert.Equal(t, w.Name, fetched.Name)

	conditions, err := repos.Waivers.ListConditions(context.Background(), w.ID)
	require.NoError(t, err)
	assert.Len(t, conditions, 1)
	assert.Equal(t, "severity_rank", conditions[0].Field)

	contexts, err := repos.Waivers.ListContexts(context.Background(), w.ID)
	require.NoError(t, err)
	assert.Len(t, contexts, 1)

	targets, err := repos.Waivers.ListFindingTargets(context.Background(), w.ID)
	require.NoError(t, err)
	assert.Len(t, targets, 1)

	events, err := repos.Waivers.ListEvents(context.Background(), w.ID)
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "created", events[0].EventType)

	toggled, err := repos.Waivers.Toggle(context.Background(), w.ID, project.ID)
	require.NoError(t, err)
	assert.False(t, toggled.Enabled)

	active, err := repos.Waivers.ListActive(context.Background(), project.ID)
	require.NoError(t, err)
	assert.Len(t, active, 0)

	_, err = repos.Waivers.Delete(context.Background(), w.ID, project.ID)
	require.NoError(t, err)

	_, err = repos.Waivers.GetByID(context.Background(), w.ID, project.ID)
	assert.Error(t, err)
}

func TestScanScopeHashRoundTrip(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	project := createTestProject(t, repos)

	expectedHash := "abc123deadbeef"
	report, err := repos.Reports.Create(context.Background(), CreateReportParams{
		ProjectID:     project.ID,
		ToolName:      "trivy",
		ToolVersion:   pgtype.Text{Valid: false},
		ScanType:      "image",
		ScanTarget:    pgtype.Text{String: "myapp:latest", Valid: true},
		ScanScope:     []byte(`{}`),
		ScanScopeHash: pgtype.Text{String: expectedHash, Valid: true},
		Branch:        pgtype.Text{Valid: false},
		CommitSha:     pgtype.Text{Valid: false},
		RawReportHash: pgtype.Text{Valid: false},
		ParserVersion: pgtype.Text{Valid: false},
	})
	require.NoError(t, err)
	assert.True(t, report.ScanScopeHash.Valid)
	assert.Equal(t, expectedHash, report.ScanScopeHash.String)
}

func TestRawDataRoundTrip(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	project := createTestProject(t, repos)

	rawData := []byte(`{"scanner":"trivy","results":[]}`)
	report, err := repos.Reports.Create(context.Background(), CreateReportParams{
		ProjectID:     project.ID,
		ToolName:      "trivy",
		ToolVersion:   pgtype.Text{Valid: false},
		ScanType:      "image",
		ScanTarget:    pgtype.Text{Valid: false},
		ScanScope:     []byte(`{}`),
		ScanScopeHash: pgtype.Text{Valid: false},
		Branch:        pgtype.Text{Valid: false},
		CommitSha:     pgtype.Text{Valid: false},
		RawData:       rawData,
		RawReportHash: pgtype.Text{Valid: false},
		ParserVersion: pgtype.Text{Valid: false},
	})
	require.NoError(t, err)

	fetched, err := repos.Reports.GetByID(context.Background(), report.ID)
	require.NoError(t, err)
	assert.Equal(t, rawData, fetched.RawData)
}
