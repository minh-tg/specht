//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Rolling back past the membership backfill must keep ordinary memberships.
// 000036's down renames member to viewer first, so a backfill down that
// deletes every viewer row removed all of them.
func TestDownMigrations_KeepMembershipsPastTheBackfill(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	pool := repos.pool

	m, err := migrate.New("file://../../migrations", pool.Config().ConnString())
	require.NoError(t, err)
	defer func() { _, _ = m.Close() }()

	var userID, projectID string
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO users (email, role) VALUES ('m@example.com', 'member') RETURNING id`).Scan(&userID))
	require.NoError(t, pool.QueryRow(ctx, `
		INSERT INTO projects (slug, name, deployment_threshold, settings)
		VALUES ('members-down', 'Members', 'high', '{}') RETURNING id`).Scan(&projectID))
	_, err = pool.Exec(ctx, `INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, 'member')`, projectID, userID)
	require.NoError(t, err)

	require.NoError(t, m.Migrate(29))
	var role string
	require.NoError(t, pool.QueryRow(ctx, `SELECT role FROM project_members WHERE project_id = $1 AND user_id = $2`, projectID, userID).Scan(&role))
	assert.Equal(t, "viewer", role, "the membership survives the rollback under its old role name")

	require.NoError(t, m.Up())
	require.NoError(t, pool.QueryRow(ctx, `SELECT role FROM project_members WHERE project_id = $1 AND user_id = $2`, projectID, userID).Scan(&role))
	assert.Equal(t, "member", role)
}
