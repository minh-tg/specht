//go:build integration

package db

import (
	"context"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minh-tg/specht/internal/testimage"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	tcexec "github.com/testcontainers/testcontainers-go/exec"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	appRoleScript = "/docker-entrypoint-initdb.d/10-specht-app-role.sql"
	appPassword   = "app-role-test-password"
)

// appRoleDB is a Postgres started the way deploy/docker-compose.yml starts it:
// the deploy init script creates specht_app before any migration has run.
type appRoleDB struct {
	container  testcontainers.Container
	host, port string
}

func startAppRoleDB(t *testing.T) *appRoleDB {
	t.Helper()
	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        testimage.Postgres(),
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":          "specht",
				"POSTGRES_PASSWORD":      "specht",
				"POSTGRES_DB":            "specht",
				"SPECHT_APP_DB_PASSWORD": appPassword,
			},
			Files: []testcontainers.ContainerFile{{
				HostFilePath:      "../../deploy/postgres/initdb/10-specht-app-role.sql",
				ContainerFilePath: appRoleScript,
				FileMode:          0o644,
			}},
			WaitingFor: wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = container.Terminate(context.Background()) })
	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)
	return &appRoleDB{container: container, host: host, port: port.Port()}
}

func (d *appRoleDB) dsn(user, password, database string) string {
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable", user, password, d.host, d.port, database)
}

// runScript runs the init script inside the container, the way the upgrade
// steps in deploy/README.md do, and returns its exit code and output.
func (d *appRoleDB) runScript(t *testing.T, database string, env ...string) (int, string) {
	t.Helper()
	cmd := []string{"psql", "-v", "ON_ERROR_STOP=1", "-U", "specht", "-d", database, "-f", appRoleScript}
	opts := []tcexec.ProcessOption{tcexec.Multiplexed()}
	if len(env) > 0 {
		opts = append(opts, tcexec.WithEnv(env))
	}
	code, out, err := d.container.Exec(context.Background(), cmd, opts...)
	require.NoError(t, err)
	raw, err := io.ReadAll(out)
	require.NoError(t, err)
	return code, string(raw)
}

func connect(t *testing.T, dsn string) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// requireDMLOnly checks that the app role can read and write every table and
// sequence in the schema and can change none of them.
func requireDMLOnly(t *testing.T, conn *pgx.Conn) {
	t.Helper()
	ctx := context.Background()

	rows, err := conn.Query(ctx, `
		SELECT c.relname, c.relkind::text,
		       has_table_privilege(c.oid, 'SELECT'), has_table_privilege(c.oid, 'INSERT'),
		       has_table_privilege(c.oid, 'UPDATE'), has_table_privilege(c.oid, 'DELETE'),
		       has_table_privilege(c.oid, 'TRUNCATE'), has_table_privilege(c.oid, 'TRIGGER'),
		       has_table_privilege(c.oid, 'REFERENCES')
		FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind IN ('r', 'p', 'v')`)
	require.NoError(t, err)
	tables := 0
	for rows.Next() {
		var name, kind string
		var sel, ins, upd, del, trunc, trig, refs bool
		require.NoError(t, rows.Scan(&name, &kind, &sel, &ins, &upd, &del, &trunc, &trig, &refs))
		tables++
		require.Truef(t, sel && ins && upd && del, "%s lacks SELECT, INSERT, UPDATE or DELETE", name)
		require.Falsef(t, trunc || trig || refs, "%s grants more than DML", name)
	}
	require.NoError(t, rows.Err())
	require.Greater(t, tables, 30, "the migrated schema has its tables")

	var missing int
	require.NoError(t, conn.QueryRow(ctx, `
		SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public' AND c.relkind = 'S'
		  AND NOT (has_sequence_privilege(c.oid, 'USAGE') AND has_sequence_privilege(c.oid, 'SELECT'))`).Scan(&missing))
	require.Zero(t, missing, "every sequence is usable")

	warning, err := RuntimeRoleWarning(ctx, conn)
	require.NoError(t, err)
	require.Empty(t, warning)

	for _, stmt := range []string{
		"CREATE TABLE app_role_probe (id int)",
		"ALTER TABLE users ADD COLUMN app_role_probe int",
		"TRUNCATE waiver_deletions",
		"DROP TABLE schema_migrations",
		"ALTER TABLE waiver_deletions DISABLE TRIGGER waiver_deletions_no_delete",
	} {
		_, err := conn.Exec(ctx, stmt)
		require.Errorf(t, err, "the app role ran %q", stmt)
	}
}

func TestAppRoleScript(t *testing.T) {
	ctx := context.Background()
	pg := startAppRoleDB(t)
	owner := pg.dsn("specht", "specht", "specht")

	// Fresh install: the init script ran on an empty database, and the
	// default privileges cover every table the migrations create after it.
	require.NoError(t, RunMigrations(owner, "../../migrations"))
	app := connect(t, pg.dsn("specht_app", appPassword, "specht"))
	requireDMLOnly(t, app)

	// The server's own queries need the functions the migrations made.
	var functions, denied int
	require.NoError(t, app.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE NOT has_function_privilege(p.oid, 'EXECUTE'))
		FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
		WHERE n.nspname = 'public'`).Scan(&functions, &denied))
	require.Positive(t, functions, "the migrations create functions")
	require.Zero(t, denied, "the app role may call every function")

	t.Run("the owner is reported", func(t *testing.T) {
		warning, err := RuntimeRoleWarning(ctx, connect(t, owner))
		require.NoError(t, err)
		require.Contains(t, warning, "superuser")
	})

	t.Run("running it again is harmless", func(t *testing.T) {
		code, out := pg.runScript(t, "specht")
		require.Zerof(t, code, "rerun failed: %s", out)
		requireDMLOnly(t, connect(t, pg.dsn("specht_app", appPassword, "specht")))
	})

	t.Run("an existing install gains the role", func(t *testing.T) {
		// A database migrated before the role script ever ran on it.
		_, err := connect(t, owner).Exec(ctx, "CREATE DATABASE legacy")
		require.NoError(t, err)
		require.NoError(t, RunMigrations(pg.dsn("specht", "specht", "legacy"), "../../migrations"))
		code, out := pg.runScript(t, "legacy")
		require.Zerof(t, code, "upgrade run failed: %s", out)
		requireDMLOnly(t, connect(t, pg.dsn("specht_app", appPassword, "legacy")))
	})

	t.Run("a missing password is refused", func(t *testing.T) {
		code, out := pg.runScript(t, "specht", "SPECHT_APP_DB_PASSWORD=")
		require.NotZero(t, code)
		require.Contains(t, out, "SPECHT_APP_DB_PASSWORD is not set")
	})

	t.Run("an elevated role is refused", func(t *testing.T) {
		_, err := connect(t, owner).Exec(ctx, "CREATE ROLE specht_elevated LOGIN CREATEDB")
		require.NoError(t, err)
		code, out := pg.runScript(t, "specht", "SPECHT_APP_DB_USER=specht_elevated")
		require.NotZero(t, code)
		require.True(t, strings.Contains(out, "NOCREATEDB"), out)
	})
}
