//go:build integration

package repo

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/lifecycle"
	"github.com/minh-tg/specht/internal/port"
)

// TestRawRetention_ClearsOnlyOldPayloads runs the real sweep against the database. An old settled
// report loses its raw_data and reads as expired, a new report and the findings both keep their
// data, and a report that never had a payload (SQL NULL, as before migration 000012) is not
// reported as expired.
func TestRawRetention_ClearsOnlyOldPayloads(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "retention", Name: "Retention", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)

	newReport := func(hash string, age time.Duration) string {
		sha := hash
		r, err := stores.Reports.Create(ctx, port.CreateReportInput{
			ProjectID: project.ID, ToolName: "trivy", ScanType: "image", ScanScope: []byte(`{}`),
			RawReportHash: hash, CommitSha: &sha, ScanMode: "full", RawData: []byte(`{"Results":[]}`),
		})
		require.NoError(t, err)
		_, err = stores.Reports.UpdateStatus(ctx, r.ID, project.ID, "completed", 1, nil)
		require.NoError(t, err)
		_, err = pool.Exec(ctx, `UPDATE reports SET created_at = $2 WHERE id = $1`, r.ID, time.Now().Add(-age))
		require.NoError(t, err)
		return r.ID
	}
	old := newReport("old", 45*24*time.Hour)
	fresh := newReport("fresh", time.Hour)
	legacy := newReport("legacy", 45*24*time.Hour)
	_, err = pool.Exec(ctx, `UPDATE reports SET raw_data = NULL WHERE id = $1`, legacy)
	require.NoError(t, err)

	now := time.Now().UTC()
	finding, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
		ProjectID: project.ID, FindingKind: "sca", Fingerprint: "fp-retention", Title: "CVE-2026-0002",
		Severity: "high", SeverityRank: 3, Score: 7.0, FirstSeen: now, LastSeen: now,
	})
	require.NoError(t, err)

	rawOf := func(id string) string {
		var raw *string
		require.NoError(t, pool.QueryRow(ctx, `SELECT raw_data::text FROM reports WHERE id = $1`, id).Scan(&raw))
		if raw == nil {
			return "<sql null>"
		}
		return *raw
	}

	t.Run("a zero window keeps every payload", func(t *testing.T) {
		n, err := lifecycle.ClearExpiredRaw(ctx, stores.Reports, 0, time.Now(), logger)
		require.NoError(t, err)
		assert.Zero(t, n)
		r, err := stores.Reports.GetByID(ctx, old)
		require.NoError(t, err)
		assert.False(t, r.RawDataExpired)
		assert.Equal(t, `{"Results": []}`, rawOf(old))
	})

	t.Run("the sweep clears the old payload and keeps the rest", func(t *testing.T) {
		n, err := lifecycle.ClearExpiredRaw(ctx, stores.Reports, 30, time.Now(), logger)
		require.NoError(t, err)
		assert.EqualValues(t, 1, n, "only the report older than 30 days has a payload to clear")

		r, err := stores.Reports.GetByID(ctx, old)
		require.NoError(t, err)
		assert.True(t, r.RawDataExpired)
		assert.Equal(t, "completed", r.Status, "the report row stays")
		assert.Equal(t, "null", rawOf(old), "the payload is JSON null, not SQL NULL")

		r, err = stores.Reports.GetByID(ctx, fresh)
		require.NoError(t, err)
		assert.False(t, r.RawDataExpired)
		assert.Equal(t, `{"Results": []}`, rawOf(fresh))

		r, err = stores.Reports.GetByID(ctx, legacy)
		require.NoError(t, err)
		assert.False(t, r.RawDataExpired, "a report that never had a payload is not expired")
		assert.Equal(t, "<sql null>", rawOf(legacy))

		f, err := stores.Findings.GetByID(ctx, finding.ID)
		require.NoError(t, err)
		assert.Equal(t, "CVE-2026-0002", f.CurrentTitle)
	})

	t.Run("a second sweep finds nothing left to clear", func(t *testing.T) {
		n, err := lifecycle.ClearExpiredRaw(ctx, stores.Reports, 30, time.Now(), logger)
		require.NoError(t, err)
		assert.Zero(t, n)
	})
}
