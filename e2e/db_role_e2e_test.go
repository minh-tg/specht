//go:build e2e

package e2e

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

const roleWarning = "the database role in DATABASE_URL"

// TestE2E_ServerRunsAsRestrictedRole pins the database role split: the shared
// server, which every other test drives, queries as specht_app and runs its
// migrations as the owner, and a server that queries as the owner says so.
func TestE2E_ServerRunsAsRestrictedRole(t *testing.T) {
	ctx := context.Background()

	t.Run("the shared server queries as a role that cannot change the schema", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, appDSN)
		require.NoError(t, err)
		defer func() { _ = conn.Close(ctx) }()
		var user string
		var super bool
		require.NoError(t, conn.QueryRow(ctx,
			`SELECT current_user, rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&user, &super))
		require.Equal(t, "specht_app", user)
		require.False(t, super)
		_, err = conn.Exec(ctx, "TRUNCATE waiver_deletions")
		require.ErrorContains(t, err, "permission denied")

		raw, err := os.ReadFile(serverLog.Name())
		require.NoError(t, err)
		require.NotContains(t, string(raw), roleWarning, "the shared server warned about its own role")
	})

	t.Run("migrate uses MIGRATE_DATABASE_URL", func(t *testing.T) {
		run := func(env ...string) (int, string) {
			cmd := exec.Command(serverBin, "migrate")
			cmd.Dir = repoRoot
			cmd.Env = cleanEnv(append(env, "JWT_SECRET="+randomHex(48), "LOG_LEVEL=info", "DB_MIGRATE=false")...)
			out, err := cmd.CombinedOutput()
			if exit, ok := err.(*exec.ExitError); ok {
				return exit.ExitCode(), string(out)
			}
			require.NoError(t, err)
			return 0, string(out)
		}
		code, out := run("DATABASE_URL="+appDSN, "MIGRATE_DATABASE_URL="+dsn)
		require.Zerof(t, code, "migrate as the owner failed:\n%s", out)
		require.Contains(t, out, "migrations complete")

		// A wrong owner password fails the run although DATABASE_URL works,
		// so the migrations did not fall back to DATABASE_URL.
		code, out = run("DATABASE_URL="+appDSN, "MIGRATE_DATABASE_URL="+strings.Replace(dsn, "specht:specht@", "specht:wrong@", 1))
		require.NotZerof(t, code, "migrate ignored MIGRATE_DATABASE_URL:\n%s", out)
		require.Contains(t, out, "password authentication failed")
	})

	t.Run("a server that queries as the owner warns", func(t *testing.T) {
		srv := startFreshServer(t, "role_warning_e2e")
		require.Contains(t, srv.readLog(), roleWarning+" is a superuser")
	})
}
