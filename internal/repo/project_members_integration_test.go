//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestProjectMembers_EndToEnd pins the tenant-isolation primitive against
// real Postgres: upsert (insert + role change), list, and membership checks.
func TestProjectMembers_EndToEnd(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	ports := &pgProjectPort{q: sqlc.New(repos.pool)}

	project := createTestProject(t, repos)
	user, err := repos.Users.Create(ctx, "member@test.com",
		pgtype.Text{Valid: false}, pgtype.Text{Valid: true, String: "unused-hash"})
	require.NoError(t, err)
	userID := uuid.UUID(user.ID.Bytes).String()
	projectID := uuid.UUID(project.ID.Bytes).String()

	isMember, err := ports.IsMember(ctx, projectID, userID)
	require.NoError(t, err)
	assert.False(t, isMember, "fresh user must not belong to the project")

	m, err := ports.UpsertMember(ctx, projectID, userID, "member")
	require.NoError(t, err)
	assert.Equal(t, projectID, m.ProjectID)
	assert.Equal(t, userID, m.UserID)
	assert.Equal(t, "member", m.Role)

	isMember, err = ports.IsMember(ctx, projectID, userID)
	require.NoError(t, err)
	assert.True(t, isMember)

	m, err = ports.UpsertMember(ctx, projectID, userID, "manager")
	require.NoError(t, err)
	assert.Equal(t, "manager", m.Role, "re-upsert must change the role, not duplicate")

	members, err := ports.ListMembers(ctx, projectID)
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "manager", members[0].Role)
}
