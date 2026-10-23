//go:build integration

package repo

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestStatsRepo_LatestCompletedReport(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	project := func(slug string) string {
		p, err := stores.Projects.Create(ctx, port.CreateProjectInput{
			Slug: slug, Name: slug, DeploymentThreshold: "high", Settings: []byte("{}"),
		})
		require.NoError(t, err)
		return p.ID
	}
	pid := project("report-freshness")
	foreign := project("foreign-report-freshness")
	empty := project("empty-report-freshness")
	base := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	seed := func(projectID, hash, status string, received time.Time, completed *time.Time) string {
		r, err := stores.Reports.Create(ctx, port.CreateReportInput{
			ProjectID: projectID, ToolName: "trivy", ScanType: "image",
			ScanScope: []byte("{}"), ScanMode: "full", RawReportHash: hash,
		})
		require.NoError(t, err)
		if status != "processing" {
			_, err = stores.Reports.UpdateStatus(ctx, r.ID, projectID, status, 0, nil)
			require.NoError(t, err)
		}
		_, err = pool.Exec(ctx, `UPDATE reports SET created_at = $2, completed_at = $3 WHERE id = $1`, r.ID, received, completed)
		require.NoError(t, err)
		return r.ID
	}

	// An older upload can finish after a newer one. Select completion order,
	// not receipt order, and do not stop at the latest reports page.
	late := base.Add(2 * time.Hour)
	want := seed(pid, "slow-completed", "completed", base.Add(-time.Hour), &late)
	seed(pid, "fast-completed", "completed", base, &base)
	for i := 0; i < 25; i++ {
		seed(pid, fmt.Sprintf("failed-%d", i), "failed", base.Add(time.Duration(i+3)*time.Hour), nil)
	}
	seed(pid, "processing", "processing", base.Add(30*time.Hour), nil)
	seed(foreign, "foreign", "completed", base.Add(40*time.Hour), nil)

	got, err := stores.Stats.GetProjectLatestCompletedReport(ctx, pid)
	require.NoError(t, err)
	assert.Equal(t, want, got.ID)
	assert.Equal(t, "completed", got.Status)
	require.NotNil(t, got.CompletedAt)
	assert.WithinDuration(t, late, *got.CompletedAt, time.Microsecond)
	latest, err := stores.Stats.GetProjectLatestReport(ctx, pid)
	require.NoError(t, err)
	assert.Equal(t, "processing", latest.Status)

	_, err = stores.Stats.GetProjectLatestCompletedReport(ctx, empty)
	require.ErrorIs(t, err, port.ErrNotFound)
	seed(empty, "only-failed", "failed", base, nil)
	_, err = stores.Stats.GetProjectLatestCompletedReport(ctx, empty)
	require.ErrorIs(t, err, port.ErrNotFound)

	// Legacy completed rows may lack a completion timestamp. Keep the field
	// absent and let the caller label its known receipt time instead.
	legacy := seed(empty, "legacy-completed", "completed", base.Add(-time.Hour), nil)
	got, err = stores.Stats.GetProjectLatestCompletedReport(ctx, empty)
	require.NoError(t, err)
	assert.Equal(t, legacy, got.ID)
	assert.Nil(t, got.CompletedAt)
}
