package db

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// RowQuerier runs a query that returns one row. *pgxpool.Pool and pgx.Conn
// satisfy it.
type RowQuerier interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// runtimeRoleQuery reports whether the connected role is a superuser and
// whether it owns, or may act as the owner of, a table, view or sequence in
// the schema queries resolve to. Either lets it run DDL, TRUNCATE or disable
// the append-only triggers.
const runtimeRoleQuery = `
SELECT r.rolsuper,
       EXISTS (
           SELECT 1
           FROM pg_class c
           JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = current_schema()
             AND c.relkind IN ('r', 'p', 'v', 'm', 'S')
             AND pg_has_role(current_user, c.relowner, 'MEMBER')
       )
FROM pg_roles r
WHERE r.rolname = current_user`

// RuntimeRoleWarning returns a warning when the role q connects as is a
// superuser or owns the schema's tables, and "" when it is limited to the
// privileges granted to it. The server needs only SELECT, INSERT, UPDATE and
// DELETE on the tables and USAGE on the sequences.
func RuntimeRoleWarning(ctx context.Context, q RowQuerier) (string, error) {
	var superuser, owner bool
	if err := q.QueryRow(ctx, runtimeRoleQuery).Scan(&superuser, &owner); err != nil {
		return "", fmt.Errorf("read database role: %w", err)
	}
	return runtimeRoleWarning(superuser, owner), nil
}

func runtimeRoleWarning(superuser, owner bool) string {
	const fix = "; connect DATABASE_URL as a role with only SELECT, INSERT, UPDATE and DELETE on the tables " +
		"and set MIGRATE_DATABASE_URL to the owner for migrations (deploy/README.md, \"Database roles\")"
	switch {
	case superuser:
		return "the database role in DATABASE_URL is a superuser, so a query the server runs can change the schema or run programs on the database host" + fix
	case owner:
		return "the database role in DATABASE_URL owns the schema's tables, so a query the server runs can alter, truncate or drop them" + fix
	}
	return ""
}
