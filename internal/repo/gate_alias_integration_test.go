//go:build integration

package repo

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func TestGateCandidatesLoadAliasesWithoutOtherDimensions(t *testing.T) {
	s, cleanup := newScopeSeverityScenario(t)
	defer cleanup()
	report := s.report(t, "scope", "high", 3, 0)
	require.NoError(t, s.stores.Findings.RecordReportIntroducedFindings(s.ctx, report, nil, []port.IntroducedFindingEntry{{FindingID: s.findingID, ChangeType: "new"}}))
	for _, withAliases := range []bool{false, true} {
		if withAliases {
			for _, d := range []port.DimensionInput{{FindingID: s.findingID, Key: "alias", Value: "CVE-2030-1234"}, {FindingID: s.findingID, Key: "purl", Value: "pkg:npm/example@1"}} {
				require.NoError(t, s.stores.Findings.UpsertDimension(s.ctx, d))
			}
		}
		all, err := s.stores.Findings.ListGateCandidates(s.ctx, s.projectID, 3)
		require.NoError(t, err)
		introduced, err := s.stores.Findings.ListIntroducedGateCandidates(s.ctx, s.projectID, report, 3)
		require.NoError(t, err)
		require.Len(t, all, 1)
		require.Len(t, introduced, 1)
		if withAliases {
			require.Equal(t, []string{"CVE-2030-1234"}, all[0].Aliases)
			require.Equal(t, all[0].Aliases, introduced[0].Aliases)
		} else {
			require.Empty(t, all[0].Aliases)
			require.Empty(t, introduced[0].Aliases)
		}
	}
}
