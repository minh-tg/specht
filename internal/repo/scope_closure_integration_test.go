//go:build integration

package repo

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
)

func TestVerificationRechecksEvidenceUnderLock(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()
	old := s.report(t, "main", "high", 3, time.Hour)
	_, err := s.pool.Exec(s.ctx, `UPDATE reports SET scan_completeness='complete' WHERE id=$1`, old)
	require.NoError(t, err)
	basis, err := s.stores.Reports.Create(s.ctx, port.CreateReportInput{ProjectID: s.projectID, ToolName: "trivy", ScanType: "image", ScanScopeHash: "main", ScanScope: []byte(`{}`), RawReportHash: "basis", ScanMode: "full", ScanCompleteness: "complete"})
	require.NoError(t, err)
	_, err = s.stores.Reports.UpdateStatus(s.ctx, basis.ID, s.projectID, "completed", 0, nil)
	require.NoError(t, err)
	s.report(t, "main", "critical", 4, 0)
	_, err = s.stores.Findings.MarkFixedWithEvent(s.ctx, s.findingID, basis.ID, port.FindingEventInput{FindingID: s.findingID, EventType: "verified_fixed"})
	require.ErrorIs(t, err, port.ErrFindingStillObserved)
	require.Equal(t, "open", s.finding(t).State)
	require.Len(t, s.scopes(t), 1)
}

func TestScopeClosureKeepsOtherScopesActive(t *testing.T) {
	for _, manual := range []bool{false, true} {
		t.Run(map[bool]string{false: "automatic", true: "manual"}[manual], func(t *testing.T) {
			s, cleanup := newScopeSeverityScenario(t)
			defer cleanup()
			s.report(t, "feature", "high", 3, time.Hour)
			main := s.report(t, "main", "critical", 4, time.Minute)
			_, err := s.pool.Exec(s.ctx, `UPDATE reports SET scan_completeness='complete' WHERE id=$1`, main)
			require.NoError(t, err)
			clean, err := s.stores.Reports.Create(s.ctx, port.CreateReportInput{ProjectID: s.projectID, ToolName: "trivy", ScanType: "image", ScanScopeHash: "main", ScanScope: []byte(`{}`), RawReportHash: "clean", ScanMode: "full", ScanCompleteness: "complete", CoveredFindingKinds: []string{"sca"}})
			require.NoError(t, err)
			if manual {
				_, err = s.stores.Reports.UpdateStatus(s.ctx, clean.ID, s.projectID, "completed", 0, nil)
				require.NoError(t, err)
				user, err := s.stores.Users.Create(s.ctx, "verifier@example.test", nil, nil)
				require.NoError(t, err)
				u := usecase.New(usecase.Deps{Stores: s.stores})
				result, err := u.VerifyFix(globalAdminCtx(user.ID), s.findingID)
				require.NoError(t, err)
				require.Equal(t, usecase.VerifyPresent, result.Outcome)
			} else {
				fixed, err := s.stores.Findings.MarkAbsentFindingsFixed(s.ctx, s.projectID, "main", clean.ID)
				require.NoError(t, err)
				require.Empty(t, fixed)
			}
			require.Equal(t, "open", s.finding(t).State)
			require.Equal(t, "high", s.finding(t).CurrentSeverity)
			require.Len(t, s.scopes(t), 1)
			candidates, err := s.stores.Findings.ListGateCandidates(s.ctx, s.projectID, 3)
			require.NoError(t, err)
			require.Len(t, candidates, 1)
			var events int
			require.NoError(t, s.pool.QueryRow(s.ctx, `SELECT count(*) FROM finding_events WHERE finding_id=$1 AND event_type='verified_fixed'`, s.findingID).Scan(&events))
			require.Zero(t, events)
		})
	}
}
