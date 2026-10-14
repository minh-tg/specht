//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestFailStale_SettlesOnlyOldProcessingReports(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "reaper", Name: "Reaper", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)

	newReport := func(hash string, status string, age time.Duration) string {
		sha := hash
		r, err := stores.Reports.Create(ctx, port.CreateReportInput{
			ProjectID: project.ID, ToolName: "trivy", ScanType: "image", ScanScope: []byte(`{}`),
			RawReportHash: hash, CommitSha: &sha, ScanMode: "full",
		})
		require.NoError(t, err)
		if status != "processing" {
			_, err = stores.Reports.UpdateStatus(ctx, r.ID, project.ID, status, 0, nil)
			require.NoError(t, err)
		}
		_, err = pool.Exec(ctx, `UPDATE reports SET created_at = $2 WHERE id = $1`, r.ID, time.Now().Add(-age))
		require.NoError(t, err)
		return r.ID
	}
	stranded := newReport("stranded", "processing", time.Hour)
	running := newReport("running", "processing", time.Minute)
	done := newReport("done", "completed", 3*time.Hour)

	n, err := stores.Reports.FailStale(ctx, time.Now().Add(-15*time.Minute), "interrupted")
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)

	status := func(id string) (string, *string) {
		r, err := stores.Reports.GetByID(ctx, id)
		require.NoError(t, err)
		return r.Status, r.ErrorMessage
	}
	got, msg := status(stranded)
	assert.Equal(t, "failed", got)
	require.NotNil(t, msg)
	assert.Equal(t, "interrupted", *msg)
	got, _ = status(running)
	assert.Equal(t, "processing", got, "an ingest that may still be running is left alone")
	got, _ = status(done)
	assert.Equal(t, "completed", got, "settled reports are never touched")

	n, err = stores.Reports.FailStale(ctx, time.Now().Add(-15*time.Minute), "interrupted")
	require.NoError(t, err)
	assert.Zero(t, n, "a second sweep finds nothing")
}
