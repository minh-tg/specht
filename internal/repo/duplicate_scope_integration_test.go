//go:build integration

package repo

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestDuplicateCleanupKeepsScopeLinkedToWinner(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()
	winner := s.report(t, "main", "critical", 4, time.Hour)
	loser, err := s.stores.Reports.Create(s.ctx, port.CreateReportInput{ProjectID: s.projectID, ToolName: "trivy", ScanType: "image", ScanScopeHash: "main", ScanScope: []byte(`{}`), RawReportHash: "maincritical", ScanMode: "full"})
	require.NoError(t, err)
	now := time.Now()
	_, err = s.stores.Findings.Upsert(s.ctx, port.UpsertFindingInput{ProjectID: s.projectID, FindingKind: "sca", Fingerprint: "shared", Title: "shared", Severity: "critical", SeverityRank: 4, FirstSeen: now, LastSeen: now, Scope: &port.FindingScopeSeverityInput{ScopeHash: "main", Severity: "critical", SeverityRank: 4, ReportID: loser.ID, ObservedAt: now}})
	require.NoError(t, err)
	require.NoError(t, s.stores.Reports.DeleteDuplicateReport(s.ctx, loser.ID, s.projectID, winner))
	require.Equal(t, winner, s.reportOf(t, "main"))
}

func TestCleanScanRetiresAnOlderUnlinkedScope(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()
	old := s.report(t, "main", "critical", 4, time.Hour)
	_, err := s.pool.Exec(s.ctx, `UPDATE reports SET scan_completeness='complete' WHERE id=$1`, old)
	require.NoError(t, err)
	_, err = s.pool.Exec(s.ctx, `UPDATE finding_scope_severities SET report_id=NULL WHERE finding_id=$1`, s.findingID)
	require.NoError(t, err)
	clean, err := s.stores.Reports.Create(s.ctx, port.CreateReportInput{ProjectID: s.projectID, ToolName: "trivy", ScanType: "image", ScanScopeHash: "main", ScanScope: []byte(`{}`), RawReportHash: "clean-null", ScanMode: "full", ScanCompleteness: "complete", CoveredFindingKinds: []string{"sca"}})
	require.NoError(t, err)
	fixed, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", clean.ID)
	require.NoError(t, err)
	require.Len(t, fixed, 1)
	require.Empty(t, s.scopes(t))
	require.Equal(t, "fixed", s.finding(t).State)
}
