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

// An ingest that stopped halfway leaves findings no occurrence supports. Failing
// the stale report also removes the ones it created and archives the ones it
// only brought back, and leaves every finding with evidence alone.
func TestFailStale_SettlesTheHalfWrittenFindingsOfTheReport(t *testing.T) {
	s, cleanup := newDeleteScenario(t)
	defer cleanup()
	ctx := context.Background()

	create := func(hash string, age time.Duration) string {
		commit := hash
		r, err := s.stores.Reports.Create(ctx, port.CreateReportInput{
			ProjectID: s.projectID, ToolName: "trivy", ScanType: "image", ScanScope: []byte(`{}`),
			RawReportHash: hash, CommitSha: &commit, ScanMode: "full",
		})
		require.NoError(t, err)
		s.exec(t, `UPDATE reports SET created_at = $2 WHERE id = $1`, r.ID, time.Now().Add(-age))
		return r.ID
	}
	stranded := create("stranded", time.Hour)
	running := create("running", time.Minute)

	created := s.finding(t, "created-by-stranded")
	s.introducedBy(t, created, stranded, "stranded")
	evidenced := s.finding(t, "evidenced")
	s.introducedBy(t, evidenced, stranded, "stranded")
	s.occurrence(t, evidenced, s.reportB)
	revived := s.finding(t, "revived")
	s.introducedBy(t, revived, stranded, "stranded")
	s.exec(t, `UPDATE findings SET created_at = $2 WHERE id = $1`, revived, time.Now().Add(-48*time.Hour))
	inFlight := s.finding(t, "created-by-running")
	s.introducedBy(t, inFlight, running, "running")

	n, err := s.stores.Reports.FailStale(ctx, time.Now().Add(-10*time.Minute), "interrupted")
	require.NoError(t, err)
	assert.EqualValues(t, 1, n)

	_, err = s.stores.Findings.GetByID(ctx, created)
	assert.ErrorIs(t, err, port.ErrNotFound, "a finding only the stranded ingest created is removed")
	assert.Equal(t, "open", s.get(t, evidenced).State, "a finding with an occurrence stays")
	assert.Equal(t, "archived", s.get(t, revived).State, "a finding the ingest only brought back is archived")
	assert.Equal(t, "open", s.get(t, inFlight).State, "an ingest that may still run keeps its findings")
	assert.Equal(t, "open", s.get(t, s.onlyB).State)

	events, err := s.stores.Findings.ListEvents(ctx, revived, []string{"state_changed"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, events, 1, "the archive is recorded")

	n, err = s.stores.Reports.FailStale(ctx, time.Now().Add(-10*time.Minute), "interrupted")
	require.NoError(t, err)
	assert.Zero(t, n, "a second sweep finds nothing")
}

// SettleFailedReport is the same cleanup for a report the ingest itself marked
// failed.
func TestSettleFailedReport_RemovesWhatTheReportCreatedWithoutEvidence(t *testing.T) {
	s, cleanup := newDeleteScenario(t)
	defer cleanup()
	ctx := context.Background()
	commit := "failed1"
	r, err := s.stores.Reports.Create(ctx, port.CreateReportInput{
		ProjectID: s.projectID, ToolName: "trivy", ScanType: "image", ScanScope: []byte(`{}`),
		RawReportHash: "failed1", CommitSha: &commit, ScanMode: "full",
	})
	require.NoError(t, err)
	half := s.finding(t, "half")
	s.introducedBy(t, half, r.ID, "failed1")

	msg := "Internal error: could not store findings."
	_, err = s.stores.Reports.UpdateStatus(ctx, r.ID, s.projectID, "failed", 0, &msg)
	require.NoError(t, err)
	require.NoError(t, s.stores.Reports.SettleFailedReport(ctx, r.ID, s.projectID))

	_, err = s.stores.Findings.GetByID(ctx, half)
	assert.ErrorIs(t, err, port.ErrNotFound)
	assert.Equal(t, "open", s.get(t, s.shared).State, "findings with evidence are untouched")

	require.NoError(t, s.stores.Reports.SettleFailedReport(ctx, r.ID, s.projectID), "running it twice is harmless")
}
