//go:build integration

package repo

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// A report keeps where it came from, and the stats queries that the project
// page reads return it too.
func TestReportCIContext_RoundTrips(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	project := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()

	repoURL, title, runURL := "https://github.com/acme/shop", "Bump lodash", "https://github.com/acme/shop/actions/runs/42"
	number := int32(123)
	created, err := stores.Reports.Create(ctx, port.CreateReportInput{
		ProjectID: projectID, ToolName: "trivy", ScanType: "image", ScanScope: []byte(`{}`),
		RawReportHash: "ci-context", ScanMode: "full", RawData: []byte(`{"Results":[]}`), Status: "completed",
		RepositoryURL: &repoURL, PullRequestNumber: &number, PullRequestTitle: &title, CIRunURL: &runURL,
	})
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, `UPDATE reports SET status = 'completed', completed_at = NOW() WHERE id = $1`, mustParseID(created.ID))
	require.NoError(t, err)

	for name, load := range map[string]func() (port.Report, error){
		"by id":  func() (port.Report, error) { return stores.Reports.GetByID(ctx, created.ID) },
		"latest": func() (port.Report, error) { return stores.Stats.GetProjectLatestReport(ctx, projectID) },
		"latest completed": func() (port.Report, error) {
			return stores.Stats.GetProjectLatestCompletedReport(ctx, projectID)
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := load()
			require.NoError(t, err)
			require.NotNil(t, got.RepositoryURL)
			assert.Equal(t, repoURL, *got.RepositoryURL)
			require.NotNil(t, got.PullRequestNumber)
			assert.Equal(t, number, *got.PullRequestNumber)
			require.NotNil(t, got.PullRequestTitle)
			assert.Equal(t, title, *got.PullRequestTitle)
			require.NotNil(t, got.CIRunURL)
			assert.Equal(t, runURL, *got.CIRunURL)
		})
	}

	bare, err := stores.Reports.Create(ctx, port.CreateReportInput{
		ProjectID: projectID, ToolName: "trivy", ScanType: "image", ScanScope: []byte(`{}`),
		RawReportHash: "no-ci-context", ScanMode: "full", RawData: []byte(`{"Results":[]}`), Status: "completed",
	})
	require.NoError(t, err)
	got, err := stores.Reports.GetByID(ctx, bare.ID)
	require.NoError(t, err)
	assert.Nil(t, got.RepositoryURL)
	assert.Nil(t, got.PullRequestNumber)
	assert.Nil(t, got.PullRequestTitle)
	assert.Nil(t, got.CIRunURL)
}

// The database refuses what the API refuses, so a caller that skips the API
// checks still cannot store a credential or a script link.
func TestMigration000078_ChecksTheLinks(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	project := createTestProject(t, repos)

	insert := func(column, value string) error {
		_, err := repos.pool.Exec(ctx, `INSERT INTO reports (project_id, tool_name, scan_type, scan_scope, status, `+column+`)
			VALUES ($1, 'trivy', 'image', '{}', 'completed', $2)`, project.ID, value)
		return err
	}
	for _, column := range []string{"repository_url", "ci_run_url"} {
		t.Run(column, func(t *testing.T) {
			require.NoError(t, insert(column, "https://github.com/acme/shop/actions/runs/1"))
			require.NoError(t, insert(column, "http://git.internal:8080/acme/shop"))
			for _, bad := range []string{
				"https://gitlab-ci-token:glcbt-secret@gitlab.com/acme/shop.git",
				"javascript:alert(1)",
				"HTTPS://github.com/acme",
				"https://github.com/acme shop",
				"https:///acme",
			} {
				assert.Error(t, insert(column, bad), bad)
			}
		})
	}
	_, err := repos.pool.Exec(ctx, `INSERT INTO reports (project_id, tool_name, scan_type, scan_scope, status, pull_request_number)
		VALUES ($1, 'trivy', 'image', '{}', 'completed', 0)`, project.ID)
	assert.Error(t, err, "a pull request number starts at 1")
}

// The migration goes down and up again on a database that holds reports.
func TestMigration000078_DownAndUp(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	c := pool.Config().ConnConfig
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", c.User, c.Password, c.Host, c.Port, c.Database)

	m, err := migrate.New("file://../../migrations", dsn)
	require.NoError(t, err)
	defer func() { _, _ = m.Close() }()
	if err := m.Migrate(78); err != nil {
		require.ErrorIs(t, err, migrate.ErrNoChange)
	}

	var projectID pgtype.UUID
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO projects (slug, name, deployment_threshold, settings)
		VALUES ('ci-context-down', 'CI context down', 'high', '{}') RETURNING id`).Scan(&projectID))
	_, err = pool.Exec(ctx, `INSERT INTO reports (project_id, tool_name, scan_type, scan_scope, status, repository_url, pull_request_number)
		VALUES ($1, 'trivy', 'image', '{}', 'completed', 'https://github.com/acme/shop', 7)`, projectID)
	require.NoError(t, err)

	require.NoError(t, m.Steps(-1))
	var count int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM reports WHERE project_id = $1`, projectID).Scan(&count))
	assert.Equal(t, 1, count, "going down keeps the report")
	require.NoError(t, m.Steps(1))
}
