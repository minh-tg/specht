//go:build integration

package repo

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMigration000077_BackfillsProducerNames gives generic SARIF reports whose
// payload is still kept the tool names the file gives, and leaves the rest NULL.
func TestMigration000077_BackfillsProducerNames(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	c := pool.Config().ConnConfig
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", c.User, c.Password, c.Host, c.Port, c.Database)

	m, err := migrate.New("file://../../migrations", dsn)
	require.NoError(t, err)
	defer func() { _, _ = m.Close() }()
	require.NoError(t, m.Migrate(76))

	var projectID pgtype.UUID
	require.NoError(t, pool.QueryRow(ctx, `INSERT INTO projects (slug, name, deployment_threshold, settings)
		VALUES ('producer-backfill', 'Producer backfill', 'high', '{}') RETURNING id`).Scan(&projectID))
	insert := func(tool, raw string) pgtype.UUID {
		t.Helper()
		var id pgtype.UUID
		require.NoError(t, pool.QueryRow(ctx, `INSERT INTO reports (project_id, tool_name, scan_type, scan_scope, status, raw_data)
			VALUES ($1, $2, 'filesystem', '{}', 'completed', $3::jsonb) RETURNING id`, projectID, tool, raw).Scan(&id))
		return id
	}
	run := func(name string) string { return `{"tool":{"driver":{"name":"` + name + `"}},"results":[]}` }
	twoTools := insert("sarif", `{"version":"2.1.0","runs":[`+run("Hadolint")+`,`+run("Gosec")+`,`+run("Gosec")+`,`+run("")+`]}`)
	expired := insert("sarif", `null`)
	noRuns := insert("sarif", `{"version":"2.1.0"}`)
	ownScanner := insert("semgrep", `{"version":"2.1.0","runs":[`+run("Semgrep OSS")+`]}`)

	require.NoError(t, m.Steps(1))

	producer := func(id pgtype.UUID) *string {
		t.Helper()
		var name *string
		require.NoError(t, pool.QueryRow(ctx, `SELECT producer_name FROM reports WHERE id = $1`, id).Scan(&name))
		return name
	}
	got := producer(twoTools)
	require.NotNil(t, got)
	assert.Equal(t, "Gosec, Hadolint", *got, "distinct names, empty ones left out")
	assert.Nil(t, producer(expired), "an expired payload has nothing to read")
	assert.Nil(t, producer(noRuns))
	assert.Nil(t, producer(ownScanner), "a scanner with its own name keeps it")

	require.NoError(t, m.Steps(-1))
	require.NoError(t, m.Steps(1))
}
