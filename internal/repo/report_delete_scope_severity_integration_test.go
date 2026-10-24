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

// A report delete removes the severity evidence it supplied. When other
// evidence remains, the aggregate follows it; when none does, the finding keeps
// its historical severity.
type scopeSeverityScenario struct {
	ctx       context.Context
	pool      *pgxpool.Pool
	stores    *port.Stores
	projectID string
	findingID string
}

func newScopeSeverityScenario(t *testing.T) (*scopeSeverityScenario, func()) {
	t.Helper()
	pool, cleanup := setupIngestPool(t)
	ctx := context.Background()
	stores := NewPortStores(pool)
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "scope-del", Name: "Scope Del", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	now := time.Now()
	finding, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
		ProjectID: project.ID, FindingKind: "sca", Fingerprint: "shared", Title: "shared",
		Severity: "critical", SeverityRank: 5, Score: 9, FirstSeen: now, LastSeen: now,
	})
	require.NoError(t, err)
	return &scopeSeverityScenario{
		ctx: ctx, pool: pool, stores: stores, projectID: project.ID, findingID: finding.ID,
	}, cleanup
}

// report records one completed scan in a scope: the finding upsert with its
// scope severity, an occurrence, and attribution on first evidence, the same
// order ingest writes them.
func (s *scopeSeverityScenario) report(t *testing.T, scope, severity string, rank int16, age time.Duration) string {
	t.Helper()
	observed := time.Now().Add(-age)
	r, err := s.stores.Reports.Create(s.ctx, port.CreateReportInput{
		ProjectID: s.projectID, ToolName: "trivy", ScanType: "image", ScanScopeHash: scope,
		ScanScope: []byte(`{}`), RawReportHash: scope + severity, ScanMode: "full",
	})
	require.NoError(t, err)
	_, err = s.stores.Reports.UpdateStatus(s.ctx, r.ID, s.projectID, "completed", 1, nil)
	require.NoError(t, err)
	_, err = s.stores.Findings.Upsert(s.ctx, port.UpsertFindingInput{
		ProjectID: s.projectID, FindingKind: "sca", Fingerprint: "shared", Title: "shared",
		Severity: severity, SeverityRank: rank, Score: 9, FirstSeen: observed, LastSeen: observed,
		Scope: &port.FindingScopeSeverityInput{
			ScopeHash: scope, Severity: severity, SeverityRank: rank,
			ReportID: r.ID, ObservedAt: observed,
		},
	})
	require.NoError(t, err)
	id := r.ID
	_, err = s.stores.Findings.CreateOccurrence(s.ctx, port.OccurrenceInput{
		FindingID: s.findingID, ReportID: &id, Title: "shared", Severity: severity,
		SeverityRank: rank, ToolName: "trivy", ObservedAt: observed,
		Display: []byte(`{}`), Metadata: []byte(`{}`),
	})
	require.NoError(t, err)
	current, err := s.stores.Findings.GetByID(s.ctx, s.findingID)
	require.NoError(t, err)
	if current.IntroducedByReportID == nil {
		_, err = s.stores.Findings.SetFindingIntroducedBy(s.ctx, s.findingID, r.ID, nil)
		require.NoError(t, err)
	}
	return r.ID
}

func (s *scopeSeverityScenario) deleteReport(t *testing.T, id string) {
	t.Helper()
	_, err := s.stores.Reports.DeleteReportAndSettle(s.ctx, id, s.projectID, nil)
	require.NoError(t, err)
}

func (s *scopeSeverityScenario) finding(t *testing.T) port.Finding {
	t.Helper()
	f, err := s.stores.Findings.GetByID(s.ctx, s.findingID)
	require.NoError(t, err)
	return f
}

func (s *scopeSeverityScenario) scopes(t *testing.T) []port.FindingScopeSeverity {
	t.Helper()
	scopes, err := s.stores.Findings.ListScopeSeverities(s.ctx, []string{s.findingID})
	require.NoError(t, err)
	return scopes
}

func (s *scopeSeverityScenario) reportOf(t *testing.T, scope string) string {
	t.Helper()
	var reportID string
	err := s.pool.QueryRow(s.ctx,
		`SELECT report_id::text FROM finding_scope_severities WHERE finding_id = $1 AND scope_hash = $2`,
		s.findingID, scope).Scan(&reportID)
	require.NoError(t, err)
	return reportID
}

func TestDeleteReportAndSettle_DropsSeverityFromTheDeletedReportsScope(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()
	mainReport := s.report(t, "main-scope", "critical", 5, time.Hour)
	featureReport := s.report(t, "feature-scope", "high", 4, 0)
	require.Equal(t, "critical", s.finding(t).CurrentSeverity, "the maximum across live scopes")

	s.deleteReport(t, mainReport)

	after := s.finding(t)
	assert.Equal(t, "open", after.State, "the feature-scope report still shows it")
	assert.Equal(t, "high", after.CurrentSeverity,
		"the deleted report's critical severity must not outlive its evidence")
	assert.EqualValues(t, 4, after.CurrentSeverityRank)

	scopes := s.scopes(t)
	require.Len(t, scopes, 1)
	assert.Equal(t, "feature-scope", scopes[0].ScopeHash)
	assert.Equal(t, featureReport, s.reportOf(t, "feature-scope"))
}

func TestDeleteReportAndSettle_RestoresTheSameScopesOlderObservation(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()
	older := s.report(t, "main-scope", "high", 4, time.Hour)
	newer := s.report(t, "main-scope", "critical", 5, 0)
	require.Equal(t, "critical", s.finding(t).CurrentSeverity)

	s.deleteReport(t, newer)

	after := s.finding(t)
	assert.Equal(t, "open", after.State)
	assert.Equal(t, "high", after.CurrentSeverity,
		"the older report in the same scope is still evidence")
	assert.EqualValues(t, 4, after.CurrentSeverityRank)
	assert.Equal(t, older, s.reportOf(t, "main-scope"))
}

func TestDeleteReportAndSettle_KeepsHistoricalSeverityWhenNoEvidenceRemains(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()
	only := s.report(t, "main-scope", "critical", 5, 0)

	s.deleteReport(t, only)

	after := s.finding(t)
	assert.Equal(t, "archived", after.State)
	assert.Equal(t, "critical", after.CurrentSeverity, "the documented historical fallback")
	assert.Empty(t, s.scopes(t), "no live scope claims the severity")
}

// A finding the advisory watcher created has no introducing report. When a
// later scan observes it, deleting that report must settle it rather than fail
// because the comparison was SQL NULL.
func TestDeleteReportAndSettle_SettlesAFindingWithNoIntroducingReport(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()
	report := s.report(t, "main-scope", "critical", 5, 0)
	now := time.Now()
	unattributed, err := s.stores.Findings.Upsert(s.ctx, port.UpsertFindingInput{
		ProjectID: s.projectID, FindingKind: "sca", Fingerprint: "watcher", Title: "watcher",
		Severity: "medium", SeverityRank: 3, Score: 5, FirstSeen: now, LastSeen: now,
	})
	require.NoError(t, err)
	_, err = s.stores.Findings.CreateOccurrence(s.ctx, port.OccurrenceInput{
		FindingID: unattributed.ID, ReportID: &report, Title: "watcher", Severity: "medium",
		SeverityRank: 3, ToolName: "trivy", ObservedAt: now,
		Display: []byte(`{}`), Metadata: []byte(`{}`),
	})
	require.NoError(t, err)

	s.deleteReport(t, report)

	after, err := s.stores.Findings.GetByID(s.ctx, unattributed.ID)
	require.NoError(t, err)
	assert.Equal(t, "archived", after.State)
}
