// Package testimage names the container images that integration and e2e tests start.
package testimage

import "os"

// PostgresEnv overrides the Postgres image. CI sets it to a mirror so test runs do not
// pull from Docker Hub; unset, tests use the public image.
const PostgresEnv = "SPECHT_TEST_POSTGRES_IMAGE"

const defaultPostgres = "postgres:17-alpine"

// Postgres returns the image reference for the test database.
func Postgres() string {
	if ref := os.Getenv(PostgresEnv); ref != "" {
		return ref
	}
	return defaultPostgres
}
