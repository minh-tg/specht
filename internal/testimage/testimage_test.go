package testimage

import "testing"

func TestPostgres(t *testing.T) {
	t.Run("default", func(t *testing.T) {
		t.Setenv(PostgresEnv, "")
		if got := Postgres(); got != "postgres:17-alpine" {
			t.Fatalf("Postgres() = %q, want the public image", got)
		}
	})
	t.Run("override", func(t *testing.T) {
		t.Setenv(PostgresEnv, "ghcr.io/example/mirror/postgres:17-alpine")
		if got := Postgres(); got != "ghcr.io/example/mirror/postgres:17-alpine" {
			t.Fatalf("Postgres() = %q, want the override", got)
		}
	})
}
