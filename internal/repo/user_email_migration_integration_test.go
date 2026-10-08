//go:build integration

package repo

import (
	"context"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUsers_EmailStorageAndLookupIgnoreCase(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	created, err := repos.Users.Create(ctx, "Ada@Example.COM",
		pgtype.Text{Valid: false}, pgtype.Text{Valid: true, String: "unused-hash"})
	require.NoError(t, err)
	assert.Equal(t, "ada@example.com", created.Email, "the database lowercases even if a caller forgets to")

	found, err := repos.Users.GetByEmail(ctx, "ADA@example.com")
	require.NoError(t, err)
	assert.Equal(t, created.ID, found.ID, "lookup ignores case")

	_, err = repos.Users.Create(ctx, "aDa@EXAMPLE.com",
		pgtype.Text{Valid: false}, pgtype.Text{Valid: true, String: "unused-hash"})
	assert.Error(t, err, "a case-variant address cannot become a second account")
}

func TestUserEmailMigration_RefusesCaseDuplicatesThenNormalises(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()

	m, err := migrate.New("file://../../migrations", repos.pool.Config().ConnString())
	require.NoError(t, err)
	defer func() { _, _ = m.Close() }()

	require.NoError(t, m.Migrate(36), "step back to before the normalisation migration")
	_, err = repos.pool.Exec(ctx, `
		INSERT INTO users (email, role) VALUES
			('Dup@Example.com', 'member'),
			('dup@example.com', 'member'),
			('Mixed@Example.com', 'member')`)
	require.NoError(t, err)

	err = m.Up()
	require.Error(t, err, "case-only duplicates must stop the migration")
	assert.Contains(t, err.Error(), "case-insensitive duplicates exist (dup@example.com)")

	// The operator resolves the pair and retries from the last good version.
	_, err = repos.pool.Exec(ctx, `DELETE FROM users WHERE email = 'dup@example.com'`)
	require.NoError(t, err)
	require.NoError(t, m.Force(36))
	require.NoError(t, m.Up())

	var emails []string
	rows, err := repos.pool.Query(ctx, `SELECT email FROM users WHERE lower(email) IN ('dup@example.com', 'mixed@example.com') ORDER BY email`)
	require.NoError(t, err)
	for rows.Next() {
		var e string
		require.NoError(t, rows.Scan(&e))
		emails = append(emails, e)
	}
	require.NoError(t, rows.Err())
	assert.Equal(t, []string{"dup@example.com", "mixed@example.com"}, emails, "stored addresses are lowercased")

	_, err = repos.pool.Exec(ctx, `INSERT INTO users (email, role) VALUES ('MIXED@example.com', 'member')`)
	assert.Error(t, err, "uniqueness now ignores case")

	require.NoError(t, m.Steps(-1), "rolling back restores the original casing")
	var restored string
	require.NoError(t, repos.pool.QueryRow(ctx, `SELECT email FROM users WHERE lower(email) = 'mixed@example.com'`).Scan(&restored))
	assert.Equal(t, "Mixed@Example.com", restored)

	require.NoError(t, m.Up(), "up, down, up must be repeatable")
}
