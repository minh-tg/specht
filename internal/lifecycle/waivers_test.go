//go:build integration

package lifecycle

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/xMinhx/specht/internal/db"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

func setupLifecycleTestDB(t *testing.T) (*pgxpool.Pool, func()) {
	t.Helper()
	ctx := context.Background()

	req := testcontainers.ContainerRequest{
		Image:        "postgres:17-alpine",
		ExposedPorts: []string{"5432/tcp"},
		Env: map[string]string{
			"POSTGRES_USER":     "specht",
			"POSTGRES_PASSWORD": "specht",
			"POSTGRES_DB":       "specht_test",
		},
		WaitingFor: wait.ForLog("database system is ready to accept connections").
			WithOccurrence(2).
			WithStartupTimeout(60 * time.Second),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)

	host, err := container.Host(ctx)
	require.NoError(t, err)
	port, err := container.MappedPort(ctx, "5432")
	require.NoError(t, err)

	dsn := fmt.Sprintf("postgres://specht:specht@%s:%s/specht_test?sslmode=disable", host, port.Port())

	err = db.RunMigrations(dsn, "../../migrations")
	require.NoError(t, err, "migrations must apply")

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)

	cleanup := func() {
		pool.Close()
		container.Terminate(ctx)
	}

	return pool, cleanup
}

func insertLifecycleWaiver(t *testing.T, pool *pgxpool.Pool, projectID pgtype.UUID, name string, enabled bool, expiresAt pgtype.Timestamptz) pgtype.UUID {
	t.Helper()

	var id pgtype.UUID
	err := pool.QueryRow(context.Background(),
		`INSERT INTO waivers (project_id, name, description, enabled, expires_at)
		 VALUES ($1, $2, $3, $4, $5)
		 RETURNING id`,
		projectID, name, "test waiver for lifecycle", enabled, expiresAt,
	).Scan(&id)
	require.NoError(t, err)
	return id
}

func TestSweepExpiredWaivers_DisablesExpired(t *testing.T) {
	pool, cleanup := setupLifecycleTestDB(t)
	defer cleanup()

	q := sqlc.New(pool)
	ctx := context.Background()

	// Create a project
	project, err := q.CreateProject(ctx, sqlc.CreateProjectParams{
		Slug:                "test-sweep-" + uuid.New().String()[:8],
		Name:                "Test Sweep",
		Description:         pgtype.Text{Valid: false},
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	require.NoError(t, err)

	// Insert an expired waiver
	expiredID := insertLifecycleWaiver(t, pool, project.ID, "expired-waiver", true, pgtype.Timestamptz{
		Time:  time.Now().Add(-1 * time.Hour),
		Valid: true,
	})

	// Insert a non-expired waiver
	notExpiredID := insertLifecycleWaiver(t, pool, project.ID, "not-expired-waiver", true, pgtype.Timestamptz{
		Time:  time.Now().Add(24 * time.Hour),
		Valid: true,
	})

	// Insert a waiver with no expiry
	noExpiryID := insertLifecycleWaiver(t, pool, project.ID, "no-expiry-waiver", true, pgtype.Timestamptz{Valid: false})

	// Insert a waiver already disabled
	alreadyDisabledID := insertLifecycleWaiver(t, pool, project.ID, "already-disabled", false, pgtype.Timestamptz{
		Time:  time.Now().Add(-1 * time.Hour),
		Valid: true,
	})

	// Run sweep
	result, err := sweepExpiredWaivers(ctx, q, slog.Default())
	require.NoError(t, err)
	assert.Len(t, result, 1, "only one waiver should be disabled")

	// Verify expired waiver is now disabled
	updatedExpired, err := q.GetWaiver(ctx, sqlc.GetWaiverParams{
		ID: expiredID, ProjectID: project.ID,
	})
	require.NoError(t, err)
	assert.False(t, updatedExpired.Enabled, "expired waiver should be disabled")
	assert.Equal(t, "expired-waiver", result[0].Name)
	assert.Equal(t, expiredID.Bytes, result[0].ID.Bytes)

	// Verify non-expired waiver is still enabled
	updatedNotExpired, err := q.GetWaiver(ctx, sqlc.GetWaiverParams{
		ID: notExpiredID, ProjectID: project.ID,
	})
	require.NoError(t, err)
	assert.True(t, updatedNotExpired.Enabled, "non-expired waiver should still be enabled")

	// Verify no-expiry waiver is still enabled
	updatedNoExpiry, err := q.GetWaiver(ctx, sqlc.GetWaiverParams{
		ID: noExpiryID, ProjectID: project.ID,
	})
	require.NoError(t, err)
	assert.True(t, updatedNoExpiry.Enabled, "no-expiry waiver should still be enabled")

	// Verify already-disabled waiver stays disabled
	updatedAlready, err := q.GetWaiver(ctx, sqlc.GetWaiverParams{
		ID: alreadyDisabledID, ProjectID: project.ID,
	})
	require.NoError(t, err)
	assert.False(t, updatedAlready.Enabled, "already-disabled waiver should stay disabled")

	// Verify an event was created for the expired waiver
	events, err := q.ListWaiverEvents(ctx, expiredID)
	require.NoError(t, err)
	require.Len(t, events, 1, "should have one event for expired waiver")
	assert.Equal(t, "auto_disabled", events[0].EventType)

	var metadata map[string]interface{}
	err = json.Unmarshal(events[0].Metadata, &metadata)
	require.NoError(t, err)
	assert.Equal(t, "waiver_expired", metadata["reason"])
	assert.Equal(t, "expired-waiver", metadata["waiver_name"])

	// Verify no events for non-expired waiver
	eventsNE, err := q.ListWaiverEvents(ctx, notExpiredID)
	require.NoError(t, err)
	assert.Len(t, eventsNE, 0, "no events for non-expired waiver")
}

func TestRunWaiverExpiry_TickerDisablesExpired(t *testing.T) {
	pool, cleanup := setupLifecycleTestDB(t)
	defer cleanup()

	q := sqlc.New(pool)
	ctx := context.Background()

	// Create a project
	project, err := q.CreateProject(ctx, sqlc.CreateProjectParams{
		Slug:                "test-ticker-" + uuid.New().String()[:8],
		Name:                "Test Ticker",
		Description:         pgtype.Text{Valid: false},
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	require.NoError(t, err)

	// Insert an expired waiver
	waiverID := insertLifecycleWaiver(t, pool, project.ID, "ticker-expired", true, pgtype.Timestamptz{
		Time:  time.Now().Add(-1 * time.Hour),
		Valid: true,
	})

	// Start the expiry goroutine with a fast interval
	ctx2, cancel := context.WithCancel(context.Background())
	defer cancel()

	RunWaiverExpiry(ctx2, pool, 100*time.Millisecond, slog.Default())

	// Wait for at least 2 ticks
	time.Sleep(500 * time.Millisecond)

	// Verify the waiver was disabled
	updated, err := q.GetWaiver(ctx, sqlc.GetWaiverParams{
		ID: waiverID, ProjectID: project.ID,
	})
	require.NoError(t, err)
	assert.False(t, updated.Enabled, "ticker should have disabled expired waiver")

	// Verify event was created
	events, err := q.ListWaiverEvents(ctx, waiverID)
	require.NoError(t, err)
	assert.Len(t, events, 1)
	assert.Equal(t, "auto_disabled", events[0].EventType)
}

func TestRunWaiverExpiry_NonExpiredUntouched(t *testing.T) {
	pool, cleanup := setupLifecycleTestDB(t)
	defer cleanup()

	q := sqlc.New(pool)
	ctx := context.Background()

	project, err := q.CreateProject(ctx, sqlc.CreateProjectParams{
		Slug:                "test-non-expired-" + uuid.New().String()[:8],
		Name:                "Test Non Expired",
		Description:         pgtype.Text{Valid: false},
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	require.NoError(t, err)

	// Non-expired waiver
	waiverID := insertLifecycleWaiver(t, pool, project.ID, "still-valid", true, pgtype.Timestamptz{
		Time:  time.Now().Add(24 * time.Hour),
		Valid: true,
	})

	ctx2, cancel := context.WithCancel(context.Background())
	defer cancel()

	RunWaiverExpiry(ctx2, pool, 100*time.Millisecond, slog.Default())

	time.Sleep(500 * time.Millisecond)

	updated, err := q.GetWaiver(ctx, sqlc.GetWaiverParams{
		ID: waiverID, ProjectID: project.ID,
	})
	require.NoError(t, err)
	assert.True(t, updated.Enabled, "non-expired waiver should remain enabled")
}
