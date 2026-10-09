//go:build integration

package repo

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minh-tg/specht/internal/db"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
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

func TestReportRepo_FailedStatusKeepsErrorMessage(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	project, err := repos.Projects.Create(context.Background(), sqlc.CreateProjectParams{
		Slug:                "failed-app",
		Name:                "Failed App",
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

	reason := "Internal error: could not store findings."
	_, err = repos.Reports.UpdateStatus(context.Background(), report.ID, project.ID, "failed", 0, pgtype.Text{String: reason, Valid: true})
	require.NoError(t, err)

	failed, err := repos.Reports.GetByID(context.Background(), report.ID)
	require.NoError(t, err)
	assert.Equal(t, "failed", failed.Status)
	assert.Equal(t, pgtype.Text{String: reason, Valid: true}, failed.ErrorMessage)
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

	findings, err := repos.Findings.ListByProject(context.Background(), project.ID, port.ListFindingsParams{Limit: 10, Offset: 0})
	require.NoError(t, err)
	assert.Len(t, findings, 1)

	criticalFindings, err := repos.Findings.ListByProject(context.Background(), project.ID, port.ListFindingsParams{Severities: []string{"critical"}, Limit: 10, Offset: 0})
	require.NoError(t, err)
	assert.Len(t, criticalFindings, 1)

	lowFindings, err := repos.Findings.ListByProject(context.Background(), project.ID, port.ListFindingsParams{Severities: []string{"low"}, Limit: 10, Offset: 0})
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

	expiry := time.Date(2030, 6, 30, 12, 0, 0, 0, time.UTC)
	key, err := repos.APIKeys.Create(context.Background(), sqlc.CreateAPIKeyParams{
		ProjectID: project.ID,
		Name:      "ci-key",
		KeyPrefix: "vuln_abc",
		KeyHash:   "abc123hash",
		LastFour:  pgtype.Text{String: "1234", Valid: true},
		Scopes:    []byte(`["ingest"]`),
		ExpiresAt: pgtype.Timestamptz{Time: expiry, Valid: true},
	})
	require.NoError(t, err)
	assert.True(t, key.ID.Valid)
	assert.False(t, key.RevokedAt.Valid)
	assert.True(t, key.ExpiresAt.Valid)
	assert.WithinDuration(t, expiry, key.ExpiresAt.Time, time.Second)
	assert.False(t, key.LastUsedAt.Valid, "a fresh key has never been used")

	keys, err := repos.APIKeys.ListByProject(context.Background(), project.ID)
	require.NoError(t, err)
	assert.Len(t, keys, 1)

	fetched, err := repos.APIKeys.GetByHash(context.Background(), "abc123hash")
	require.NoError(t, err)
	assert.Equal(t, "ci-key", fetched.Name)
	require.True(t, fetched.CreatedBy.Valid)
	assert.True(t, fetched.ExpiresAt.Valid)
	assert.WithinDuration(t, expiry, fetched.ExpiresAt.Time, time.Second)
	actor, err := repos.Users.GetByID(context.Background(), fetched.CreatedBy)
	require.NoError(t, err)
	assert.Equal(t, fetched.CreatedBy.Bytes, actor.ID.Bytes)

	// TouchLastUsed stamps last_used_at and leaves the key usable; it is a
	// no-op for revoked keys (guarded by revoked_at IS NULL).
	err = repos.APIKeys.TouchLastUsed(context.Background(), key.ID)
	require.NoError(t, err)
	touched, err := repos.APIKeys.GetByHash(context.Background(), "abc123hash")
	require.NoError(t, err)
	assert.True(t, touched.LastUsedAt.Valid)
	assert.WithinDuration(t, time.Now(), touched.LastUsedAt.Time, time.Minute)

	revoked, err := repos.APIKeys.Revoke(context.Background(), key.ID, project.ID)
	require.NoError(t, err)
	assert.True(t, revoked.RevokedAt.Valid)

	keysAfterRevoke, err := repos.APIKeys.ListByProject(context.Background(), project.ID)
	require.NoError(t, err)
	assert.Len(t, keysAfterRevoke, 0)
}

// TestAPIKeyRepo_GetByHash_NullCreatedByFallsBackOnlyToSystemUser pins the
// actor-resolution contract for legacy API keys (created before migration
// 000021 added created_by): a key whose created_by is NULL must resolve to
// the system user and never to another tenant's user. The historical query
// fell back through project members, then any member, then the system user,
// then the oldest user in the whole database — misattributing cross-tenant
// actors whenever the oldest account belonged to a different project.
func TestAPIKeyRepo_GetByHash_NullCreatedByFallsBackOnlyToSystemUser(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	systemUser, err := repos.Users.GetByEmail(ctx, "system@specht.local")
	require.NoError(t, err)

	// Oldest user in the DB belongs to a different tenant: the flawed
	// fallback chain's final rung would pick this account over the system
	// user. Real deployments had users before migration 000021 inserted the
	// system account, so backdate this user to predate it.
	otherTenant, err := repos.Users.Create(ctx, "oldest-other-tenant@test.com",
		pgtype.Text{Valid: false}, pgtype.Text{Valid: true, String: "unused-hash"})
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx,
		`UPDATE users SET created_at = NOW() - interval '10 years' WHERE id = $1`,
		uuid.UUID(otherTenant.ID.Bytes).String())
	require.NoError(t, err)
	otherProject := createTestProject(t, repos)
	_, err = repos.Users.Create(ctx, "other-tenant-member@test.com",
		pgtype.Text{Valid: false}, pgtype.Text{Valid: true, String: "unused-hash"})
	require.NoError(t, err)

	// Key's own project has an admin member the flawed chain preferred over
	// the system user.
	project := createTestProject(t, repos)
	projectAdmin, err := repos.Users.Create(ctx, "admin@test.com",
		pgtype.Text{Valid: false}, pgtype.Text{Valid: true, String: "unused-hash"})
	require.NoError(t, err)

	// Insert the project-member rows directly: repository methods for
	// membership management do not exist yet.
	for projectID, member := range map[pgtype.UUID]sqlc.User{
		otherProject.ID: otherTenant,
		project.ID:      projectAdmin,
	} {
		_, err := repos.pool.Exec(ctx, `
			INSERT INTO project_members (project_id, user_id, role)
			VALUES ($1, $2, 'admin')
			ON CONFLICT (project_id, user_id) DO NOTHING`,
			uuid.UUID(projectID.Bytes).String(), uuid.UUID(member.ID.Bytes).String())
		require.NoError(t, err)
	}

	// Legacy key: created_by NULL (no created_by in CreateAPIKeyParams).
	key, err := repos.APIKeys.Create(ctx, sqlc.CreateAPIKeyParams{
		ProjectID: project.ID,
		Name:      "legacy-ci-key",
		KeyPrefix: "vuln_legacy",
		KeyHash:   "legacyhash",
		LastFour:  pgtype.Text{String: "9999", Valid: true},
		Scopes:    []byte(`["ingest"]`),
	})
	require.NoError(t, err)
	require.False(t, key.CreatedBy.Valid, "legacy key must be created without a creator")

	fetched, err := repos.APIKeys.GetByHash(ctx, "legacyhash")
	require.NoError(t, err)
	require.True(t, fetched.CreatedBy.Valid, "lookup must always resolve an actor")

	assert.Equal(t, systemUser.ID.Bytes, fetched.CreatedBy.Bytes,
		"NULL created_by must resolve to the system user, never to the project admin or another tenant's user")

	actor, err := repos.Users.GetByID(ctx, fetched.CreatedBy)
	require.NoError(t, err)
	assert.Equal(t, "system@specht.local", actor.Email)
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

func TestWaiverToggleAndAuditEventAreAtomic(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	project := createTestProject(t, repos)
	waiver, err := repos.Waivers.Create(ctx, sqlc.CreateWaiverParams{
		ProjectID: project.ID,
		Name:      "atomic-toggle",
		Enabled:   true,
	})
	require.NoError(t, err)

	_, err = repos.pool.Exec(ctx, `
		ALTER TABLE waiver_events
		ADD CONSTRAINT test_reject_toggle_events CHECK (event_type NOT IN ('enabled', 'disabled'))
	`)
	require.NoError(t, err)

	stores := NewPortStores(repos.pool)
	_, err = stores.Waivers.ToggleWithEvent(ctx, toUUID(waiver.ID), toUUID(project.ID), "actor-1")
	require.Error(t, err, "the audit insert constraint must fail the combined operation")

	unchanged, err := repos.Waivers.GetByID(ctx, waiver.ID, project.ID)
	require.NoError(t, err)
	assert.True(t, unchanged.Enabled, "a failed audit write must roll back the waiver toggle")
	events, err := repos.Waivers.ListEvents(ctx, waiver.ID)
	require.NoError(t, err)
	assert.Empty(t, events, "a failed transaction must not leave a partial audit event")

	_, err = repos.pool.Exec(ctx, `ALTER TABLE waiver_events DROP CONSTRAINT test_reject_toggle_events`)
	require.NoError(t, err)

	disabled, err := stores.Waivers.ToggleWithEvent(ctx, toUUID(waiver.ID), toUUID(project.ID), "actor-1")
	require.NoError(t, err)
	assert.False(t, disabled.Enabled)
	enabled, err := stores.Waivers.ToggleWithEvent(ctx, toUUID(waiver.ID), toUUID(project.ID), "actor-1")
	require.NoError(t, err)
	assert.True(t, enabled.Enabled)

	events, err = repos.Waivers.ListEvents(ctx, waiver.ID)
	require.NoError(t, err)
	require.Len(t, events, 2)
	eventTypes := map[string]bool{}
	for _, event := range events {
		eventTypes[event.EventType] = true
		assert.Equal(t, "actor-1", event.ActorID.String)
	}
	assert.True(t, eventTypes["disabled"])
	assert.True(t, eventTypes["enabled"])
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
	// RawData is stored in a JSONB column; Postgres canonicalizes key order
	// and whitespace, so compare the decoded JSON rather than raw bytes.
	assert.JSONEq(t, string(rawData), string(fetched.RawData))
}

func countInventoryRows(t *testing.T, repos *Repos, reportID pgtype.UUID) int {
	t.Helper()
	var n int
	err := repos.pool.QueryRow(context.Background(),
		"SELECT count(*) FROM report_packages WHERE report_id = $1", reportID).Scan(&n)
	require.NoError(t, err)
	return n
}

// TestInventoryRepo_PersistsPackages_SecondIngestBumpsLastSeenAt covers the
// acceptance criterion: an ingest with an N-vuln / M-clean package set
// persists N+M rows, and a second identical ingest bumps last_seen_at without
// duplicating any row.
func TestInventoryRepo_PersistsPackages_SecondIngestBumpsLastSeenAt(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	project := createTestProject(t, repos)

	report, err := repos.Reports.Create(ctx, CreateReportParams{
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

	// Vulnerable and clean packages alike land in inventory — the repo
	// persists whatever the ingest pipeline hands it, metadata included.
	packages := []UpsertReportPackageParams{
		{
			PURL:         "pkg:npm/lodash@4.17.20",
			Ecosystem:    pgtype.Text{String: "npm", Valid: true},
			Name:         pgtype.Text{String: "lodash", Valid: true},
			Version:      pgtype.Text{String: "4.17.20", Valid: true},
			ManifestPath: pgtype.Text{String: "package-lock.json", Valid: true},
		},
		{
			PURL:      "pkg:golang/github.com/gin-gonic/gin@v1.9.1",
			Ecosystem: pgtype.Text{String: "Go", Valid: true},
			Name:      pgtype.Text{String: "github.com/gin-gonic/gin", Valid: true},
			Version:   pgtype.Text{String: "v1.9.1", Valid: true},
		},
		{PURL: "pkg:deb/debian/openssl@3.0.0-1"},
	}

	// First ingest: N+M rows persisted with the report targeting set.
	err = repos.Inventory.UpsertReportPackages(ctx, report.ID, packages)
	require.NoError(t, err)
	assert.Equal(t, len(packages), countInventoryRows(t, repos, report.ID))

	var firstSeen pgtype.Timestamptz
	err = repos.pool.QueryRow(ctx,
		"SELECT last_seen_at FROM report_packages WHERE report_id = $1 AND purl = $2",
		report.ID, "pkg:npm/lodash@4.17.20").Scan(&firstSeen)
	require.NoError(t, err)
	assert.True(t, firstSeen.Time.After(time.Now().Add(-time.Minute)))

	// Identical second ingest: still N+M rows ...
	time.Sleep(1100 * time.Millisecond)
	err = repos.Inventory.UpsertReportPackages(ctx, report.ID, packages)
	require.NoError(t, err)
	assert.Equal(t, len(packages), countInventoryRows(t, repos, report.ID),
		"repeat ingest must not duplicate package rows")

	// ... but last_seen_at is bumped server-side (NOW()) on the conflict path.
	var secondSeen pgtype.Timestamptz
	err = repos.pool.QueryRow(ctx,
		"SELECT last_seen_at FROM report_packages WHERE report_id = $1 AND purl = $2",
		report.ID, "pkg:npm/lodash@4.17.20").Scan(&secondSeen)
	require.NoError(t, err)
	assert.True(t, secondSeen.Time.After(firstSeen.Time),
		"second ingest must bump last_seen_at (got %s after %s)", secondSeen.Time.Format(time.RFC3339Nano), firstSeen.Time.Format(time.RFC3339Nano))
}

func TestInventoryRepo_DistinctInventory_FiltersByTTL(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	project := createTestProject(t, repos)

	mkReport := func() sqlc.Report {
		report, err := repos.Reports.Create(ctx, CreateReportParams{
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
		return report
	}
	reportA := mkReport()
	reportB := mkReport()

	for _, reportID := range []pgtype.UUID{reportA.ID, reportB.ID} {
		err := repos.Inventory.UpsertReportPackages(ctx, reportID, []UpsertReportPackageParams{
			{PURL: "pkg:npm/lodash@4.17.20", Name: pgtype.Text{String: "lodash", Valid: true}},
			{PURL: "pkg:npm/express@4.19.2", Name: pgtype.Text{String: "express", Valid: true}},
		})
		require.NoError(t, err)
	}

	// Age lodash out of the TTL window in reportA only; reportB's copies must
	// still surface, collapsed by DISTINCT across reports.
	_, err := repos.pool.Exec(ctx,
		"UPDATE report_packages SET last_seen_at = NOW() - interval '180 days' WHERE report_id = $1 AND purl = $2",
		reportA.ID, "pkg:npm/lodash@4.17.20")
	require.NoError(t, err)

	since := pgtype.Interval{Microseconds: 90 * 24 * int64(time.Hour/time.Microsecond), Valid: true}
	rows, err := repos.Inventory.DistinctInventory(ctx, project.ID, since)
	require.NoError(t, err)
	require.Len(t, rows, 2, "stale rows excluded by TTL, duplicates across reports collapsed")
	assert.Equal(t, "pkg:npm/express@4.19.2", rows[0].Purl, "rows ordered by purl")
	assert.Equal(t, "pkg:npm/lodash@4.17.20", rows[1].Purl)
}

func TestInventoryRepo_DeleteReportPackages_ClearsAndCascades(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	project := createTestProject(t, repos)

	report, err := repos.Reports.Create(ctx, CreateReportParams{
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

	packages := []UpsertReportPackageParams{
		{PURL: "pkg:npm/lodash@4.17.20"},
		{PURL: "pkg:npm/express@4.19.2"},
	}
	require.NoError(t, repos.Inventory.UpsertReportPackages(ctx, report.ID, packages))
	require.Equal(t, 2, countInventoryRows(t, repos, report.ID))

	// Explicit cleanup path removes every package row for the report.
	require.NoError(t, repos.Inventory.DeleteReportPackages(ctx, report.ID))
	assert.Equal(t, 0, countInventoryRows(t, repos, report.ID))

	// Referential integrity: deleting the report cascades to its leftover rows.
	require.NoError(t, repos.Inventory.UpsertReportPackages(ctx, report.ID, packages))
	_, err = repos.pool.Exec(ctx, "DELETE FROM reports WHERE id = $1", report.ID)
	require.NoError(t, err)
	assert.Equal(t, 0, countInventoryRows(t, repos, report.ID))
}

// TestGateQueries_CveWatcherGatePolicy covers the CVE-watcher acceptance matrix at
// the query level: cve_watcher findings gate only when the project's
// cve_watcher_gate mode admits them. 'require_triage' (the column default)
// admits only watcher findings that have been triaged (analysis_state set —
// 'unanalyzed' is the untriaged marker per migration 000009), 'immediate'
// admits all watcher findings, and 'off' admits none. Non-watcher findings
// are unaffected in every mode.

// upsertGateCandidate inserts a critical open finding used by the batch
// gate-candidate integration test.
func upsertGateCandidate(t *testing.T, repos *Repos, ctx context.Context, project sqlc.Project, kind, title string) sqlc.Finding {
	t.Helper()
	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	f, err := repos.Findings.Upsert(ctx, UpsertFindingParams{
		ProjectID:    project.ID,
		FindingKind:  kind,
		Fingerprint:  title,
		CurrentTitle: title,
		Severity:     "critical",
		SeverityRank: 4,
		Score:        pgtype.Numeric{Valid: false},
		FirstSeenAt:  now,
		LastSeenAt:   now,
	})
	require.NoError(t, err)
	return f
}

// triageGateCandidate moves a finding off the unanalyzed marker the way the
// triage use case does: analysis_state set, gate_effect stays block.
func triageGateCandidate(t *testing.T, repos *Repos, ctx context.Context, f sqlc.Finding) sqlc.Finding {
	t.Helper()
	updated, err := repos.Findings.UpdateAnalysis(ctx, UpdateAnalysisParams{
		ID:                f.ID,
		AnalysisState:     "exploitable",
		GateEffect:        "block",
		AnalysisExpiresAt: pgtype.Timestamptz{Valid: false},
		AnalysisReason:    pgtype.Text{Valid: false},
		AnalysisSource:    "manual",
		ManualOverride:    true,
		ReviewRequired:    false,
		AnalysisUpdatedBy: pgtype.UUID{Valid: false},
	})
	require.NoError(t, err)
	return updated
}

// TestGateQueries_BatchCandidates asserts the batch gate-candidate loader is
// a pure prefilter: it returns every blocking finding (state open, gate_effect
// block, rank >= floor) with its latest reachability in one round trip. The
// cve_watcher mode policy and reachability exemptions are gate-core behavior
// (gate.GatePolicy / reachabilityExemptsFromGate) and are no longer applied
// in SQL.
func TestGateQueries_BatchCandidates(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	blockedTitles := func(t *testing.T, project sqlc.Project) []string {
		t.Helper()
		rows, err := repos.Findings.ListBlockingFindings(ctx, project.ID, 4)
		require.NoError(t, err)
		titles := make([]string, 0, len(rows))
		for _, r := range rows {
			titles = append(titles, r.CurrentTitle)
		}
		sort.Strings(titles)
		return titles
	}

	// All three findings are candidates at rank >= 4 regardless of the
	// project's cve_watcher_gate mode: the candidate SQL applies no policy.
	project := createTestProject(t, repos)
	upsertGateCandidate(t, repos, ctx, project, "sca", "cand-sca")
	upsertGateCandidate(t, repos, ctx, project, "cve_watcher", "cand-w-untriaged")
	triageGateCandidate(t, repos, ctx, upsertGateCandidate(t, repos, ctx, project, "cve_watcher", "cand-w-triaged"))

	assert.Equal(t, []string{"cand-sca", "cand-w-triaged", "cand-w-untriaged"}, blockedTitles(t, project),
		"ListBlockingFindings must return the full candidate set; policy is core-side")

	// Batch reachability: after an assessment is recorded, the candidate row
	// carries it in the same round trip.
	systemUser, err := repos.Users.GetByEmail(ctx, "system@specht.local")
	require.NoError(t, err)
	assessed, err := repos.Findings.ListBlockingFindings(ctx, project.ID, 4)
	require.NoError(t, err)
	require.NotEmpty(t, assessed)
	_, err = repos.Reachability.Upsert(ctx, UpsertReachabilityParams{
		FindingID:  assessed[0].ID,
		State:      "not_reachable",
		AssessedBy: systemUser.ID,
	})
	require.NoError(t, err)

	// The batch loader reports the latest assessment on the row.
	candidates, err := repos.Findings.ListGateCandidates(ctx, project.ID, 4)
	require.NoError(t, err)
	require.Len(t, candidates, 3)
	found := false
	for _, c := range candidates {
		if c.ID == assessed[0].ID {
			found = true
			assert.Equal(t, "not_reachable", string(c.ReachabilityState))
		}
	}
	assert.True(t, found, "batch candidate must carry the latest reachability")
}
