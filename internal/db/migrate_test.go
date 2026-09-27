package db

import "testing"

func TestMigrationsRejectMissingSource(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(string, string) error
	}{
		{name: "up", run: RunMigrations},
		{name: "down", run: RollbackMigrations},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.run("postgres://user:pass@localhost:5432/specht", "/path/that/does/not/exist")
			if err == nil {
				t.Fatal("migration error = nil, want source initialization error")
			}
			if got := err.Error(); len(got) < 15 || got[:15] != "migration init:" {
				t.Errorf("error = %q, want migration init prefix", got)
			}
		})
	}
}

func TestMigrationsRejectInvalidDatabaseURL(t *testing.T) {
	for _, test := range []struct {
		name string
		run  func(string, string) error
	}{
		{name: "up", run: RunMigrations},
		{name: "down", run: RollbackMigrations},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.run(":not-a-postgres-url", "/path/that/does/not/exist")
			if err == nil {
				t.Fatal("migration error = nil, want initialization error")
			}
		})
	}
}
