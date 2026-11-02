//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// Nobody signs in as the seeded system account, so a project admin seat it
// holds does not make another admin's exit safe.
func TestLastAdminGuardIgnoresTheSystemAccount(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "admin@test.com", "admin")

	projectID, admins := projectWithAdmins(t, repos, ports, 1)
	human := admins[0]
	var systemID string
	require.NoError(t, repos.pool.QueryRow(ctx, "SELECT id::text FROM users WHERE email = 'system@specht.local'").Scan(&systemID))
	// Written below the use case, as an older release could have done.
	_, err := repos.pool.Exec(ctx,
		"INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, 'admin')", projectID, systemID)
	require.NoError(t, err)

	assert.ErrorIs(t, ports.DeleteMember(ctx, projectID, human), port.ErrLastAdmin, "the system account is not another admin")
	_, err = ports.UpsertMember(ctx, projectID, human, "member")
	assert.ErrorIs(t, err, port.ErrLastAdmin)

	_, _, err = stores.Users.Deactivate(ctx, human, false)
	var sole *port.SoleProjectAdminError
	require.ErrorAs(t, err, &sole, "deactivating the only admin who can sign in names the project")

	count, err := sqlc.New(repos.pool).CountProjectAdmins(ctx, mustUUID(t, projectID))
	require.NoError(t, err)
	assert.EqualValues(t, 1, count, "only the person counts")
}

func mustUUID(t *testing.T, s string) pgtype.UUID {
	t.Helper()
	id, err := parseID(s)
	require.NoError(t, err)
	return id
}
