//go:build e2e

package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rawRetentionReport is the part of a report response the retention sweep sets.
type rawRetentionReport struct {
	RawDataExpired   bool    `json:"raw_data_expired"`
	RawDataExpiresAt *string `json:"raw_data_expires_at"`
}

// rawRetentionFinding is the part of a finding detail response the retention sweep sets.
type rawRetentionFinding struct {
	RawDataExpired   *bool   `json:"raw_data_expired"`
	RawDataExpiresAt *string `json:"raw_data_expires_at"`
}

// TestE2E_RawRetentionSweepExpiresEvidence ingests a scan, ages its report past the retention
// window, and waits for the sweep. The report and the finding it produced must then read as
// expired and dated, while the finding itself stays listed.
func TestE2E_RawRetentionSweepExpiresEvidence(t *testing.T) {
	slug := newProject(t, "retention")
	key := mintKey(t, slug)
	ingested := ingestFixture(t, slug, key, "high-medium.sarif.json")
	target := highFinding(t, slug)

	report := request[rawRetentionReport](t, http.MethodGet, "/api/v1/reports/"+ingested.ReportID, adminToken, nil, http.StatusOK)
	assert.False(t, report.RawDataExpired, "a report inside the window keeps its payload")
	assert.Nil(t, report.RawDataExpiresAt)

	ageReport(t, ingested.ReportID, 2)

	eventually(t, 30*time.Second, "the sweep expires the aged report", func() bool {
		r := request[rawRetentionReport](t, http.MethodGet, "/api/v1/reports/"+ingested.ReportID, adminToken, nil, http.StatusOK)
		return r.RawDataExpired
	})
	report = request[rawRetentionReport](t, http.MethodGet, "/api/v1/reports/"+ingested.ReportID, adminToken, nil, http.StatusOK)
	require.NotNil(t, report.RawDataExpiresAt, "an expired report is dated by its window")

	finding := request[rawRetentionFinding](t, http.MethodGet, "/api/v1/findings/"+target.ID, adminToken, nil, http.StatusOK)
	require.NotNil(t, finding.RawDataExpired)
	assert.True(t, *finding.RawDataExpired, "the finding's latest observation is the expired report")
	assert.NotNil(t, finding.RawDataExpiresAt)

	assert.NotEmpty(t, listFindings(t, slug), "the sweep keeps findings and their summaries")
}

// ageReport moves a report's created_at back so the sweep sees it as older than the window.
func ageReport(t *testing.T, reportID string, days int) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), dsn)
	require.NoError(t, err)
	defer pool.Close()
	tag, err := pool.Exec(context.Background(),
		`UPDATE reports SET created_at = now() - make_interval(days => $2) WHERE id = $1`, reportID, days)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
}
