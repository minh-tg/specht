//go:build integration

package repo

import (
	"context"
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/minh-tg/specht/internal/db"
	"github.com/minh-tg/specht/internal/testimage"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// templateDB holds the fully migrated schema. Every test clones it with
// CREATE DATABASE ... TEMPLATE, so a test gets an empty, isolated database in
// milliseconds instead of paying for a container start and all migrations.
const templateDB = "specht_test"

var (
	sharedPG struct {
		once      sync.Once
		container testcontainers.Container
		host      string
		port      string
		err       error
	}
	testDBCounter atomic.Int64
)

func TestMain(m *testing.M) {
	code := m.Run()
	if sharedPG.container != nil {
		_ = sharedPG.container.Terminate(context.Background())
	}
	os.Exit(code)
}

func startSharedPostgres() {
	ctx := context.Background()
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image:        testimage.Postgres(),
			ExposedPorts: []string{"5432/tcp"},
			Env: map[string]string{
				"POSTGRES_USER":     "specht",
				"POSTGRES_PASSWORD": "specht",
				"POSTGRES_DB":       templateDB,
			},
			// Test data is thrown away, so skip the durability work.
			Cmd: []string{"postgres", "-c", "fsync=off", "-c", "synchronous_commit=off", "-c", "full_page_writes=off"},
			WaitingFor: wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		sharedPG.err = fmt.Errorf("start postgres: %w", err)
		return
	}
	sharedPG.container = container
	if sharedPG.host, sharedPG.err = container.Host(ctx); sharedPG.err != nil {
		return
	}
	mapped, err := container.MappedPort(ctx, "5432")
	if err != nil {
		sharedPG.err = err
		return
	}
	sharedPG.port = mapped.Port()
	if err := db.RunMigrations(sharedDSN(templateDB), "../../migrations"); err != nil {
		sharedPG.err = fmt.Errorf("migrations must apply: %w", err)
	}
}

func sharedDSN(database string) string {
	return fmt.Sprintf("postgres://specht:specht@%s:%s/%s?sslmode=disable", sharedPG.host, sharedPG.port, database)
}

// newTestDatabase returns the DSN of a fresh database cloned from the migrated
// template, and a cleanup that drops it.
func newTestDatabase(t *testing.T) (string, func()) {
	t.Helper()
	ctx := context.Background()
	sharedPG.once.Do(startSharedPostgres)
	require.NoError(t, sharedPG.err)

	name := fmt.Sprintf("t%d", testDBCounter.Add(1))
	admin, err := pgx.Connect(ctx, sharedDSN("postgres"))
	require.NoError(t, err)
	defer func() { _ = admin.Close(ctx) }()
	_, err = admin.Exec(ctx, "CREATE DATABASE "+name+" TEMPLATE "+templateDB)
	require.NoError(t, err)

	return sharedDSN(name), func() {
		dropper, err := pgx.Connect(ctx, sharedDSN("postgres"))
		if err != nil {
			return
		}
		defer func() { _ = dropper.Close(ctx) }()
		_, _ = dropper.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	}
}
