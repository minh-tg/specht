//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func newProcessingReport(t *testing.T, ctx context.Context, stores *port.Stores, projectID, hash string) port.Report {
	t.Helper()
	r, err := stores.Reports.Create(ctx, port.CreateReportInput{
		ProjectID: projectID, ToolName: "trivy", ScanType: "image", ScanScope: []byte(`{}`),
		RawReportHash: hash, ScanMode: "full", RawData: []byte(`{"Results":[]}`), Status: "processing",
	})
	require.NoError(t, err)
	return r
}

// The sweep measures age on the database clock, the one that stamps
// created_at. A report created a moment ago is not stale however far the
// replica's own clock runs ahead, and one older than the limit on the database
// clock is.
func TestFailStale_MeasuresAgeOnTheDatabaseClock(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	project := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()

	fresh := newProcessingReport(t, ctx, stores, projectID, "fresh")
	old := newProcessingReport(t, ctx, stores, projectID, "old")
	_, err := repos.pool.Exec(ctx, `UPDATE reports SET created_at = NOW() - INTERVAL '11 minutes' WHERE id = $1`, mustParseID(old.ID))
	require.NoError(t, err)

	n, err := stores.Reports.FailStale(ctx, 10*time.Minute, "Interrupted")
	require.NoError(t, err)
	assert.EqualValues(t, 1, n, "only the report older than ten minutes on the database clock is reaped")

	loaded, err := stores.Reports.GetByID(ctx, fresh.ID)
	require.NoError(t, err)
	assert.Equal(t, "processing", loaded.Status)
	loaded, err = stores.Reports.GetByID(ctx, old.ID)
	require.NoError(t, err)
	assert.Equal(t, "failed", loaded.Status)
}

// An ingest that finishes after the sweep failed its report must not turn the
// report back into completed.
func TestUpdateStatus_RefusesAReportTheSweepAlreadyFailed(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	project := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()

	r := newProcessingReport(t, ctx, stores, projectID, "late")
	_, err := repos.pool.Exec(ctx, `UPDATE reports SET created_at = NOW() - INTERVAL '1 hour' WHERE id = $1`, mustParseID(r.ID))
	require.NoError(t, err)
	n, err := stores.Reports.FailStale(ctx, 10*time.Minute, "Interrupted")
	require.NoError(t, err)
	require.EqualValues(t, 1, n)

	_, err = stores.Reports.UpdateStatus(ctx, r.ID, projectID, "completed", 3, nil)
	require.ErrorIs(t, err, port.ErrReportNotProcessing)

	loaded, err := stores.Reports.GetByID(ctx, r.ID)
	require.NoError(t, err)
	assert.Equal(t, "failed", loaded.Status)
	assert.True(t, loaded.TotalFindings == nil || *loaded.TotalFindings == 0, "the late count is not written")
}

// A settled report is final: neither status can be written over the other.
func TestUpdateStatus_OnlySettlesAProcessingReport(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	project := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()

	r := newProcessingReport(t, ctx, stores, projectID, "final")
	_, err := stores.Reports.UpdateStatus(ctx, r.ID, projectID, "completed", 2, nil)
	require.NoError(t, err)

	msg := "late failure"
	_, err = stores.Reports.UpdateStatus(ctx, r.ID, projectID, "failed", 0, &msg)
	require.ErrorIs(t, err, port.ErrReportNotProcessing)
	_, err = stores.Reports.UpdateStatus(ctx, r.ID, projectID, "completed", 9, nil)
	require.ErrorIs(t, err, port.ErrReportNotProcessing)

	loaded, err := stores.Reports.GetByID(ctx, r.ID)
	require.NoError(t, err)
	assert.Equal(t, "completed", loaded.Status)
	require.NotNil(t, loaded.TotalFindings)
	assert.EqualValues(t, 2, *loaded.TotalFindings)
}
