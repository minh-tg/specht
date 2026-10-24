//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// deleteScenario seeds two reports. Report A (older, commit aaaaaaa) shows
// onlyA, reopened, fixed and shared, and introduced all four. Report B (newer,
// commit bbbbbbb) shows shared and onlyB, and introduced onlyB.
type deleteScenario struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	stores    *port.Stores
	projectID string

	reportA, reportB string
	onlyA, reopened  string
	fixed, shared    string
	onlyB            string
}

func newDeleteScenario(t *testing.T) (*deleteScenario, func()) {
	t.Helper()
	pool, cleanup := setupIngestPool(t)
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "del", Name: "Del", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	s := &deleteScenario{ctx: ctx, pool: pool, stores: stores, projectID: project.ID}

	s.reportA = s.report(t, "aaaaaaa", 48*time.Hour)
	s.reportB = s.report(t, "bbbbbbb", 24*time.Hour)

	s.onlyA = s.finding(t, "only-a")
	s.reopened = s.finding(t, "reopened")
	s.fixed = s.finding(t, "fixed")
	s.shared = s.finding(t, "shared")
	s.onlyB = s.finding(t, "only-b")
	for _, id := range []string{s.onlyA, s.reopened, s.fixed, s.shared} {
		s.occurrence(t, id, s.reportA)
		s.introducedBy(t, id, s.reportA, "aaaaaaa")
	}
	s.occurrence(t, s.shared, s.reportB)
	s.occurrence(t, s.onlyB, s.reportB)
	s.introducedBy(t, s.onlyB, s.reportB, "bbbbbbb")
	s.exec(t, `UPDATE findings SET state = 'reopened' WHERE id = $1`, s.reopened)
	s.exec(t, `UPDATE findings SET state = 'fixed' WHERE id = $1`, s.fixed)
	return s, cleanup
}

func (s *deleteScenario) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	_, err := s.pool.Exec(s.ctx, query, args...)
	require.NoError(t, err)
}

func (s *deleteScenario) report(t *testing.T, commit string, age time.Duration) string {
	t.Helper()
	sha := commit
	r, err := s.stores.Reports.Create(s.ctx, port.CreateReportInput{
		ProjectID: s.projectID, ToolName: "trivy", ScanType: "image", ScanScope: []byte(`{}`),
		RawReportHash: commit, CommitSha: &sha, ScanMode: "full",
	})
	require.NoError(t, err)
	_, err = s.stores.Reports.UpdateStatus(s.ctx, r.ID, s.projectID, "completed", 3, nil)
	require.NoError(t, err)
	s.exec(t, `UPDATE reports SET created_at = $2, completed_at = $2 WHERE id = $1`, r.ID, time.Now().Add(-age))
	return r.ID
}

func (s *deleteScenario) finding(t *testing.T, fp string) string {
	t.Helper()
	now := time.Now().UTC()
	f, err := s.stores.Findings.Upsert(s.ctx, port.UpsertFindingInput{
		ProjectID: s.projectID, FindingKind: "sca", Fingerprint: fp, Title: fp,
		Severity: "high", SeverityRank: 3, Score: 7.0, FirstSeen: now, LastSeen: now,
	})
	require.NoError(t, err)
	return f.ID
}

func (s *deleteScenario) occurrence(t *testing.T, findingID, reportID string) {
	t.Helper()
	rid := reportID
	_, err := s.stores.Findings.CreateOccurrence(s.ctx, port.OccurrenceInput{
		FindingID: findingID, ReportID: &rid, Title: "t", Severity: "high", SeverityRank: 3,
		ToolName: "trivy", ObservedAt: time.Now().UTC(), Display: []byte(`{}`), Metadata: []byte(`{}`),
	})
	require.NoError(t, err)
}

func (s *deleteScenario) introducedBy(t *testing.T, findingID, reportID, commit string) {
	t.Helper()
	_, err := s.stores.Findings.SetFindingIntroducedBy(s.ctx, findingID, reportID, &commit)
	require.NoError(t, err)
}

func (s *deleteScenario) get(t *testing.T, id string) port.Finding {
	t.Helper()
	f, err := s.stores.Findings.GetByID(s.ctx, id)
	require.NoError(t, err)
	return f
}

func TestDeleteReportAndSettle_ArchivesFindingsThatLostTheirEvidence(t *testing.T) {
	s, cleanup := newDeleteScenario(t)
	defer cleanup()
	actor, err := s.stores.Users.Create(s.ctx, "actor@example.com", nil, nil)
	require.NoError(t, err)

	result, err := s.stores.Reports.DeleteReportAndSettle(s.ctx, s.reportA, s.projectID, &actor.ID)

	require.NoError(t, err)
	assert.Equal(t, 2, result.ArchivedFindings, "the open and the reopened finding only report A showed")

	assert.Equal(t, "archived", s.get(t, s.onlyA).State)
	assert.Equal(t, "archived", s.get(t, s.reopened).State)
	assert.Equal(t, "fixed", s.get(t, s.fixed).State, "fixed is still true of a fixed finding")
	assert.Equal(t, "open", s.get(t, s.shared).State, "report B still shows it")
	assert.Equal(t, "open", s.get(t, s.onlyB).State)

	_, err = s.stores.Reports.GetByID(s.ctx, s.reportA)
	assert.ErrorIs(t, err, port.ErrNotFound)

	events, err := s.stores.Findings.ListEvents(s.ctx, s.onlyA, []string{"report_deleted"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, actor.ID, *events[0].UserID)
	assert.Equal(t, "open", *events[0].OldValue)
	assert.Equal(t, "archived", *events[0].NewValue)
	events, err = s.stores.Findings.ListEvents(s.ctx, s.reopened, []string{"report_deleted"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "reopened", *events[0].OldValue, "the event keeps the state the finding left")
	events, err = s.stores.Findings.ListEvents(s.ctx, s.shared, []string{"report_deleted"}, 10, 0)
	require.NoError(t, err)
	assert.Empty(t, events)
}

func TestDeleteReportAndSettle_RepointsAttributionToTheEarliestRemainingReport(t *testing.T) {
	s, cleanup := newDeleteScenario(t)
	defer cleanup()

	_, err := s.stores.Reports.DeleteReportAndSettle(s.ctx, s.reportA, s.projectID, nil)
	require.NoError(t, err)

	shared := s.get(t, s.shared)
	require.NotNil(t, shared.IntroducedByReportID)
	assert.Equal(t, s.reportB, *shared.IntroducedByReportID)
	require.NotNil(t, shared.IntroducedCommitSha)
	assert.Equal(t, "bbbbbbb", *shared.IntroducedCommitSha)

	onlyB := s.get(t, s.onlyB)
	assert.Equal(t, s.reportB, *onlyB.IntroducedByReportID, "untouched")

	// The archived finding has no report left to name.
	assert.Nil(t, s.get(t, s.onlyA).IntroducedByReportID)
}

func TestDeleteReportAndSettle_ArchivedFindingsDoNotCountBlockOrAge(t *testing.T) {
	s, cleanup := newDeleteScenario(t)
	defer cleanup()

	before, err := s.stores.Stats.GetProjectStats(s.ctx, s.projectID)
	require.NoError(t, err)
	require.EqualValues(t, 4, countOf(before), "onlyA, reopened, shared and onlyB are open before")

	_, err = s.stores.Reports.DeleteReportAndSettle(s.ctx, s.reportA, s.projectID, nil)
	require.NoError(t, err)

	after, err := s.stores.Stats.GetProjectStats(s.ctx, s.projectID)
	require.NoError(t, err)
	assert.EqualValues(t, 2, countOf(after), "shared and onlyB remain")
	candidates, err := s.stores.Findings.ListGateCandidates(s.ctx, s.projectID, 0)
	require.NoError(t, err)
	assert.Len(t, candidates, 2, "archived findings do not block")
	rows, _, err := s.stores.Stats.GetAgingRows(s.ctx, s.projectID)
	require.NoError(t, err)
	assert.Len(t, rows, 2, "archived findings do not age")
	weekly, err := s.stores.Stats.GetNewFindingCounts(s.ctx, s.projectID, time.Now().AddDate(0, 0, -14))
	require.NoError(t, err)
	var introduced int32
	for _, w := range weekly {
		introduced += w.Count
	}
	assert.EqualValues(t, 3, introduced, "the trend counts the fixed finding but not the archived ones")
}

func countOf(rows []port.SeverityStat) int32 {
	var n int32
	for _, r := range rows {
		n += r.Count
	}
	return n
}

func TestDeleteReportAndSettle_ArchivedFindingsStayReadableButOutOfTheDefaultList(t *testing.T) {
	s, cleanup := newDeleteScenario(t)
	defer cleanup()
	_, err := s.stores.Reports.DeleteReportAndSettle(s.ctx, s.reportA, s.projectID, nil)
	require.NoError(t, err)

	list, err := s.stores.Findings.ListByProject(s.ctx, s.projectID, port.ListFindingsParams{Limit: 50})
	require.NoError(t, err)
	ids := map[string]bool{}
	for _, f := range list {
		ids[f.ID] = true
	}
	assert.False(t, ids[s.onlyA], "archived findings are not in the default list")
	assert.True(t, ids[s.fixed], "fixed ones still are")

	archived, err := s.stores.Findings.ListByProject(s.ctx, s.projectID, port.ListFindingsParams{States: []string{"archived"}, Limit: 50})
	require.NoError(t, err)
	assert.Len(t, archived, 2, "asking for them returns them")
	count, err := s.stores.Findings.CountByProject(s.ctx, s.projectID, port.ListFindingsParams{})
	require.NoError(t, err)
	assert.EqualValues(t, 3, count, "the total follows the same rule")
}

func TestDeleteReportAndSettle_RefusesAProcessingReportAndOtherProjects(t *testing.T) {
	s, cleanup := newDeleteScenario(t)
	defer cleanup()
	s.exec(t, `UPDATE reports SET status = 'processing' WHERE id = $1`, s.reportA)

	_, err := s.stores.Reports.DeleteReportAndSettle(s.ctx, s.reportA, s.projectID, nil)
	assert.ErrorIs(t, err, port.ErrReportProcessing)
	assert.Equal(t, "open", s.get(t, s.onlyA).State, "nothing changed")
	_, err = s.stores.Reports.GetByID(s.ctx, s.reportA)
	assert.NoError(t, err)

	other, err := s.stores.Projects.Create(s.ctx, port.CreateProjectInput{
		Slug: "other", Name: "Other", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	_, err = s.stores.Reports.DeleteReportAndSettle(s.ctx, s.reportB, other.ID, nil)
	assert.ErrorIs(t, err, port.ErrNotFound, "a report is only deletable through its own project")
	_, err = s.stores.Reports.DeleteReportAndSettle(s.ctx, "00000000-0000-4000-8000-000000000999", s.projectID, nil)
	assert.ErrorIs(t, err, port.ErrNotFound)
}

func TestDeleteReportAndSettle_ASecondScanRevivesAnArchivedFinding(t *testing.T) {
	s, cleanup := newDeleteScenario(t)
	defer cleanup()
	_, err := s.stores.Reports.DeleteReportAndSettle(s.ctx, s.reportA, s.projectID, nil)
	require.NoError(t, err)
	require.Equal(t, "archived", s.get(t, s.onlyA).State)

	again := s.finding(t, "only-a")

	assert.Equal(t, s.onlyA, again)
	assert.Equal(t, "open", s.get(t, s.onlyA).State, "seeing it again opens it, as a new finding rather than a regression")
}

func TestReportDeletionImpact_CountsWhatTheDeleteWouldSettle(t *testing.T) {
	s, cleanup := newDeleteScenario(t)
	defer cleanup()

	impact, err := s.stores.Reports.ReportDeletionImpact(s.ctx, s.reportA, s.projectID)
	require.NoError(t, err)
	assert.Equal(t, 4, impact.AffectedFindings, "onlyA, reopened, fixed and shared cite report A")
	assert.Equal(t, 2, impact.ArchivedFindings, "onlyA and reopened lose their only evidence")

	_, err = s.stores.Reports.GetByID(s.ctx, s.reportA)
	require.NoError(t, err, "a preview changes nothing")

	_, err = s.stores.Reports.ReportDeletionImpact(s.ctx, s.reportA, "00000000-0000-4000-8000-0000000000ff")
	assert.ErrorIs(t, err, port.ErrNotFound, "a foreign project cannot preview another report")
}

func TestDeleteStaleReports_SettlesFindingsLikeAnExplicitDelete(t *testing.T) {
	s, cleanup := newDeleteScenario(t)
	defer cleanup()

	ids, err := s.stores.Reports.DeleteStaleReports(s.ctx, time.Now().Add(-36*time.Hour), 100)

	require.NoError(t, err)
	assert.Equal(t, []string{s.reportA}, ids, "only the older report is stale")
	assert.Equal(t, "archived", s.get(t, s.onlyA).State)
	assert.Equal(t, "open", s.get(t, s.shared).State)
	shared := s.get(t, s.shared)
	assert.Equal(t, s.reportB, *shared.IntroducedByReportID)
	events, err := s.stores.Findings.ListEvents(s.ctx, s.onlyA, []string{"report_deleted"}, 10, 0)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Nil(t, events[0].UserID, "a retention purge is the system's doing")
}
