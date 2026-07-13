//go:build integration

package lifecycle_test

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
	"github.com/xMinhx/specht/internal/lifecycle"
)

func setupTestDB(t *testing.T) (*pgxpool.Pool, func()) {
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

func createTestProject(t *testing.T, q *sqlc.Queries) sqlc.Project {
	t.Helper()
	project, err := q.CreateProject(context.Background(), sqlc.CreateProjectParams{
		Slug:                "test-" + uuid.New().String()[:8],
		Name:                "Test Project",
		Description:         pgtype.Text{Valid: false},
		DeploymentThreshold: "high",
		Settings:            []byte("{}"),
	})
	require.NoError(t, err)
	return project
}

func createTestFinding(t *testing.T, q *sqlc.Queries, projectID pgtype.UUID, fingerprint string, expiresAt pgtype.Timestamptz) sqlc.Finding {
	t.Helper()
	now := pgtype.Timestamptz{Time: time.Now(), Valid: true}
	f, err := q.UpsertFinding(context.Background(), sqlc.UpsertFindingParams{
		ProjectID:           projectID,
		FindingKind:         "sca",
		Fingerprint:         fingerprint,
		CurrentTitle:        "CVE-test",
		CurrentSeverity:     "high",
		CurrentSeverityRank: 3,
		CurrentScore:        pgtype.Numeric{Valid: false},
		State:               "open",
		TriageStatus:        "untriaged",
		FirstSeenAt:         now,
		LastSeenAt:          now,
	})
	require.NoError(t, err)

	// Set analysis state via update
	_, err = q.UpdateFindingAnalysis(context.Background(), sqlc.UpdateFindingAnalysisParams{
		ID:                f.ID,
		AnalysisState:     "false_positive",
		GateEffect:        "ignore",
		AnalysisExpiresAt: expiresAt,
		AnalysisReason:    pgtype.Text{String: "test override", Valid: true},
		AnalysisSource:    "manual",
		ManualOverride:    true,
		ReviewRequired:    false,
		AnalysisUpdatedBy: pgtype.UUID{Valid: false},
	})
	require.NoError(t, err)

	// Fetch the updated finding to get current state
	updated, err := q.GetFindingByID(context.Background(), f.ID)
	require.NoError(t, err)
	return updated
}

func TestSweepExpiredFindings_ExpiredFindingsGetReset(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	q := sqlc.New(pool)

	project := createTestProject(t, q)

	// Create a finding with expired analysis
	expiredTime := pgtype.Timestamptz{Time: time.Now().Add(-1 * time.Hour), Valid: true}
	expiredFinding := createTestFinding(t, q, project.ID, "expired-1", expiredTime)

	// Create a finding with non-expired analysis
	futureTime := pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true}
	nonExpiredFinding := createTestFinding(t, q, project.ID, "not-expired-1", futureTime)

	// Create a finding with no expiry set
	nullExpiry := pgtype.Timestamptz{Valid: false}
	noExpiryFinding := createTestFinding(t, q, project.ID, "no-expiry-1", nullExpiry)

	// Sanity checks: confirm initial state
	initialExpired, err := q.GetFindingByID(ctx, expiredFinding.ID)
	require.NoError(t, err)
	assert.Equal(t, "false_positive", initialExpired.AnalysisState)
	assert.Equal(t, "ignore", initialExpired.GateEffect)

	initialNonExpired, err := q.GetFindingByID(ctx, nonExpiredFinding.ID)
	require.NoError(t, err)
	assert.Equal(t, "false_positive", initialNonExpired.AnalysisState)
	assert.Equal(t, "ignore", initialNonExpired.GateEffect)

	// Act
	logger := slog.Default()
	count, err := lifecycle.SweepExpiredFindings(ctx, pool, logger)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "only the expired finding should be swept")

	// Assert: expired finding is reset
	refetchedExpired, err := q.GetFindingByID(ctx, expiredFinding.ID)
	require.NoError(t, err)
	assert.Equal(t, "unanalyzed", refetchedExpired.AnalysisState)
	assert.Equal(t, "block", refetchedExpired.GateEffect)
	assert.False(t, refetchedExpired.AnalysisExpiresAt.Valid, "analysis_expires_at should be null")

	// Assert: non-expired finding is untouched
	refetchedNonExpired, err := q.GetFindingByID(ctx, nonExpiredFinding.ID)
	require.NoError(t, err)
	assert.Equal(t, "false_positive", refetchedNonExpired.AnalysisState)
	assert.Equal(t, "ignore", refetchedNonExpired.GateEffect)
	assert.True(t, refetchedNonExpired.AnalysisExpiresAt.Valid)
	assert.True(t, refetchedNonExpired.AnalysisExpiresAt.Time.After(time.Now()))

	// Assert: no-expiry finding is untouched
	refetchedNoExpiry, err := q.GetFindingByID(ctx, noExpiryFinding.ID)
	require.NoError(t, err)
	assert.Equal(t, "false_positive", refetchedNoExpiry.AnalysisState)
	assert.Equal(t, "ignore", refetchedNoExpiry.GateEffect)
	assert.False(t, refetchedNoExpiry.AnalysisExpiresAt.Valid)
}

func TestSweepExpiredFindings_CreatesAnalysisChangedEvents(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	q := sqlc.New(pool)

	project := createTestProject(t, q)

	expiredTime := pgtype.Timestamptz{Time: time.Now().Add(-1 * time.Hour), Valid: true}
	finding := createTestFinding(t, q, project.ID, "expired-event-1", expiredTime)

	logger := slog.Default()
	count, err := lifecycle.SweepExpiredFindings(ctx, pool, logger)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Check events were created
	events, err := q.ListFindingEvents(ctx, sqlc.ListFindingEventsParams{
		FindingID: finding.ID,
		Column2:   []string{"analysis_changed"},
		Limit:     10,
		Offset:    0,
	})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(events), 1)

	event := events[len(events)-1] // Most recent event
	assert.Equal(t, "analysis_changed", event.EventType)

	// Verify changes JSON
	var changes map[string]interface{}
	err = json.Unmarshal(event.Changes, &changes)
	require.NoError(t, err)

	stateChanges, ok := changes["analysis_state"].(map[string]interface{})
	require.True(t, ok, "changes should contain analysis_state")
	assert.Equal(t, "false_positive", stateChanges["old"])
	assert.Equal(t, "unanalyzed", stateChanges["new"])

	gateChanges, ok := changes["gate_effect"].(map[string]interface{})
	require.True(t, ok, "changes should contain gate_effect")
	assert.Equal(t, "ignore", gateChanges["old"])
	assert.Equal(t, "block", gateChanges["new"])
}

func TestSweepExpiredFindings_NoExpiredFindings(t *testing.T) {
	pool, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	q := sqlc.New(pool)

	project := createTestProject(t, q)

	// Create only non-expired findings
	futureTime := pgtype.Timestamptz{Time: time.Now().Add(24 * time.Hour), Valid: true}
	createTestFinding(t, q, project.ID, "future-1", futureTime)

	// Act
	logger := slog.Default()
	count, err := lifecycle.SweepExpiredFindings(ctx, pool, logger)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "no findings should be swept")
}
