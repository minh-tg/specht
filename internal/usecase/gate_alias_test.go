package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/gate"
	"github.com/minh-tg/specht/internal/port"
)

func TestGateAdaptersRetainAliasOnlyCVEs(t *testing.T) {
	candidates := []port.GateCandidate{{Finding: port.Finding{ID: "finding", Fingerprint: "GHSA-example", CurrentTitle: "Vendor advisory"}, Aliases: []string{"CVE-2030-1234"}}}
	fr := &mockFindingRepo{listGateCandidatesFn: func(context.Context, string, int16) ([]port.GateCandidate, error) { return candidates, nil }}
	adapter := &gateFindingRepo{stores: &port.Stores{Findings: fr}}
	for _, introduced := range []bool{false, true} {
		var rows []gate.Finding
		var err error
		if introduced {
			rows, err = adapter.ListIntroducedGateCandidates(context.Background(), "project", "report", 3)
		} else {
			rows, err = adapter.ListBlockingFindings(context.Background(), "project", 3)
		}
		require.NoError(t, err)
		require.Len(t, rows, 1)
		require.True(t, gate.IsFindingWaived(rows[0], []gate.Waiver{{Conditions: []gate.WaiverCondition{{Field: "cve_id", Operator: "eq", Value: "CVE-2030-1234"}}}}))
	}
}

func TestWaiverPreviewMatchesAliasOnlyCVE(t *testing.T) {
	_, fr, wr, u := testCheckWaiverMatchDeps(t)
	fr.listDimensionsFn = func(context.Context, string) ([]port.FindingDimension, error) {
		return []port.FindingDimension{{Key: "alias", Value: "CVE-2030-1234"}, {Key: "purl", Value: "pkg:npm/example@1"}}, nil
	}
	wr.listActiveFn = func(context.Context, string) ([]port.Waiver, error) { return []port.Waiver{{ID: "waiver"}}, nil }
	wr.listConditionsFn = func(context.Context, string) ([]port.WaiverCondition, error) {
		return []port.WaiverCondition{{Field: "cve_id", Operator: "eq", Value: "CVE-2030-1234"}}, nil
	}
	matched, err := u.CheckWaiverMatch(sessionCtx("admin", auth.RoleAdmin), "my-app", "00000000-0000-0000-0000-0000000000a1")
	require.NoError(t, err)
	require.True(t, matched)
}
