package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xMinhx/specht/internal/port"
)

func patchHarness(t *testing.T, kind string) *Usecases {
	t.Helper()
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	commit := prcheckCommit
	report := "11111111-1111-1111-1111-111111111111"
	f := port.Finding{
		ID: "00000000-0000-0000-0000-000000000021", ProjectID: makeProject(true).ID,
		FindingKind: kind, Fingerprint: "fp1", CurrentTitle: "CVE-2024-1",
		CurrentSeverity: "high", CurrentSeverityRank: 3,
		State:                "open",
		IntroducedByReportID: &report, IntroducedCommitSha: &commit,
	}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return f, nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{ToolName: "trivy"}, nil
	}
	fr.listDimensionsFn = func(ctx context.Context, findingID string) ([]port.FindingDimension, error) {
		return []port.FindingDimension{
			{Key: "package_name", Value: "lodash"},
			{Key: "installed_version", Value: "4.17.20"},
			{Key: "fixed_version", Value: "4.17.21"},
			{Key: "file", Value: "package.json"},
		}, nil
	}
	return New(Deps{Stores: &port.Stores{
		Projects: pr, Reports: rr, Findings: fr,
		Waivers: &mockWaiverRepo{},
	}})
}

func TestPreviewPatch_SupportedBump(t *testing.T) {
	uc := patchHarness(t, "sca")
	out, err := uc.PreviewPatch(findingScopeCtx(makeProject(true).ID), "00000000-0000-0000-0000-000000000021")
	require.NoError(t, err)
	require.True(t, out.Supported)
	require.NotNil(t, out.Proposal)
	assert.Equal(t, "dependency-bump", string(out.Proposal.Class))
	assert.Equal(t, "manual", out.Proposal.ApplyMode)
}

func TestPreviewPatch_ReportEvidenceLinked(t *testing.T) {
	uc := patchHarness(t, "sca")
	out, err := uc.PreviewPatch(findingScopeCtx(makeProject(true).ID), "00000000-0000-0000-0000-000000000021")
	require.NoError(t, err)
	require.True(t, out.Supported)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", out.Proposal.Evidence.ReportID)
	assert.Equal(t, prcheckCommit, out.Proposal.Evidence.CommitSha)
	assert.Equal(t, "4.17.21", out.Proposal.Evidence.FixedVersion)
}

func TestPreviewPatch_SecretRefused(t *testing.T) {
	uc := patchHarness(t, "secret")
	out, err := uc.PreviewPatch(findingScopeCtx(makeProject(true).ID), "00000000-0000-0000-0000-000000000021")
	require.NoError(t, err)
	assert.False(t, out.Supported)
	assert.Nil(t, out.Proposal)
	assert.Contains(t, out.Reason, "never auto-patched")
}

func TestPreviewPatch_InvalidID(t *testing.T) {
	uc := patchHarness(t, "sca")
	_, err := uc.PreviewPatch(context.Background(), "not-a-uuid")
	require.Error(t, err)
}
