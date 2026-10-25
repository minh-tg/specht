package db

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// RunMigrations applies all pending migrations in the given directory.
func RunMigrations(databaseURL, migrationsPath string) (retErr error) {
	m, err := migrate.New("file://"+migrationsPath, databaseURL)
	if err != nil {
		return fmt.Errorf("migration init: %w", err)
	}
	defer func() {
		sourceErr, databaseErr := m.Close()
		if sourceErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("migration source close: %w", sourceErr))
		}
		if databaseErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("migration database close: %w", databaseErr))
		}
	}()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("migration up: %w", err)
	}

	return nil
}

// RollbackMigrations rolls back the newest applied migration, one step.
// Call it again to undo the next one. It is a no-op on an empty schema.
func RollbackMigrations(databaseURL, migrationsPath string) (retErr error) {
	m, err := migrate.New("file://"+migrationsPath, databaseURL)
	if err != nil {
		return fmt.Errorf("migration init: %w", err)
	}
	defer func() {
		sourceErr, databaseErr := m.Close()
		if sourceErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("migration source close: %w", sourceErr))
		}
		if databaseErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("migration database close: %w", databaseErr))
		}
	}()

	// Steps(-1) on an empty schema reports os.ErrNotExist, which it also
	// reports when the applied version is missing from the source, so the
	// empty case is checked first instead of swallowing that error.
	if _, _, err := m.Version(); errors.Is(err, migrate.ErrNilVersion) {
		return nil
	}
	if err := m.Steps(-1); err != nil {
		return fmt.Errorf("migration down: %w", err)
	}

	return nil
}
