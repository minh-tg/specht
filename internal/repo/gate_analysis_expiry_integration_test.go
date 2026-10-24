//go:build integration

package repo

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestGateCandidatesRespectAnalysisExpiryWithoutSweep(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()
	report := s.report(t, "scope", "high", 3, 0)
	require.NoError(t, s.stores.Findings.RecordReportIntroducedFindings(s.ctx, report, nil, []port.IntroducedFindingEntry{{FindingID: s.findingID, ChangeType: "new"}}))
	for _, tc := range []struct {
		name, expiry string
		want         int
	}{
		{"past", "NOW() - interval '1 second'", 1},
		{"now", "NOW()", 1},
		{"future", "NOW() + interval '1 hour'", 0},
		{"no expiry", "NULL", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.pool.Exec(s.ctx, `UPDATE findings SET analysis_state='accepted_risk', gate_effect='ignore', analysis_expires_at=`+tc.expiry+` WHERE id=$1`, s.findingID)
			require.NoError(t, err)
			all, err := s.stores.Findings.ListGateCandidates(s.ctx, s.projectID, 3)
			require.NoError(t, err)
			require.Len(t, all, tc.want)
			introduced, err := s.stores.Findings.ListIntroducedGateCandidates(s.ctx, s.projectID, report, 3)
			require.NoError(t, err)
			require.Len(t, introduced, tc.want)
			if tc.want > 0 {
				require.Equal(t, "unanalyzed", all[0].AnalysisState)
				require.Equal(t, "unanalyzed", introduced[0].AnalysisState)
			}
		})
	}
}
