//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Before the NULLS NOT DISTINCT key, every ingest of a digest-less artifact
// inserted a new row. The migration must merge those rows, move the
// references onto the survivor, and its down must put everything back.
func TestArtifactIdentityMigration_MergesDigestlessDuplicates(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	pool := repos.pool

	m, err := migrate.New("file://../../migrations", pool.Config().ConnString())
	require.NoError(t, err)
	defer func() { _, _ = m.Close() }()
	require.NoError(t, m.Migrate(61), "step back to before the identity migration")

	var projectID string
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, deployment_threshold, settings)
		VALUES ('dup-artifacts', 'Dup', 'high', '{}') RETURNING id`).Scan(&projectID))

	insertArtifact := func(id, name, digest, createdAt string) {
		t.Helper()
		_, err := pool.Exec(ctx, `
			INSERT INTO artifacts (id, project_id, artifact_type, name, digest, version, created_at)
			VALUES ($1, $2, 'container_image', $3, NULLIF($4, ''), $5, $6)`,
			id, projectID, name, digest, createdAt, createdAt)
		require.NoError(t, err)
	}
	const (
		oldest   = "00000000-0000-4000-8000-0000000000a1"
		middle   = "00000000-0000-4000-8000-0000000000a2"
		newest   = "00000000-0000-4000-8000-0000000000a3"
		digested = "00000000-0000-4000-8000-0000000000a4"
		other    = "00000000-0000-4000-8000-0000000000a5"
		report   = "00000000-0000-4000-8000-0000000000b1"
		waiver   = "00000000-0000-4000-8000-0000000000c1"
		context1 = "00000000-0000-4000-8000-0000000000d1"
	)
	insertArtifact(oldest, "myapp", "", "2026-01-01T00:00:00Z")
	insertArtifact(middle, "myapp", "", "2026-02-01T00:00:00Z")
	insertArtifact(newest, "myapp", "", "2026-03-01T00:00:00Z")
	insertArtifact(digested, "myapp", "sha256:aaa", "2026-01-15T00:00:00Z")
	insertArtifact(other, "other", "", "2026-01-01T00:00:00Z")

	_, err = pool.Exec(ctx, `
		INSERT INTO reports (id, project_id, tool_name, scan_type, artifact_id)
		VALUES ($1, $2, 'trivy', 'image', $3)`, report, projectID, oldest)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO waivers (id, project_id, name) VALUES ($1, $2, 'w')`, waiver, projectID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO waiver_contexts (id, waiver_id, artifact_id) VALUES ($1, $2, $3)`, context1, waiver, middle)
	require.NoError(t, err)

	artifactIDs := func() []string {
		t.Helper()
		rows, err := pool.Query(ctx, `SELECT id::text FROM artifacts WHERE project_id = $1 ORDER BY id`, projectID)
		require.NoError(t, err)
		defer rows.Close()
		var ids []string
		for rows.Next() {
			var id string
			require.NoError(t, rows.Scan(&id))
			ids = append(ids, id)
		}
		require.NoError(t, rows.Err())
		return ids
	}
	refs := func() (reportArtifact, contextArtifact string) {
		t.Helper()
		require.NoError(t, pool.QueryRow(ctx, `SELECT artifact_id::text FROM reports WHERE id = $1`, report).Scan(&reportArtifact))
		require.NoError(t, pool.QueryRow(ctx, `SELECT artifact_id::text FROM waiver_contexts WHERE id = $1`, context1).Scan(&contextArtifact))
		return reportArtifact, contextArtifact
	}

	require.NoError(t, m.Migrate(62))
	assert.Equal(t, []string{newest, digested, other}, artifactIDs(),
		"the digest-less duplicates collapse onto the newest row; digested and other names are untouched")
	r, c := refs()
	assert.Equal(t, newest, r, "the report follows its artifact to the survivor")
	assert.Equal(t, newest, c, "the waiver context follows its artifact to the survivor")

	_, err = pool.Exec(ctx, `
		INSERT INTO artifacts (project_id, artifact_type, name) VALUES ($1, 'container_image', 'myapp')`, projectID)
	require.Error(t, err, "a second digest-less row for one name is now refused")

	require.NoError(t, m.Migrate(61), "the down migration restores the merged rows")
	assert.Equal(t, []string{oldest, middle, newest, digested, other}, artifactIDs())
	r, c = refs()
	assert.Equal(t, oldest, r)
	assert.Equal(t, middle, c)

	require.NoError(t, m.Up(), "up, down, up must be repeatable")
	assert.Equal(t, []string{newest, digested, other}, artifactIDs())
}
