package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func notifyHarness(t *testing.T, state string) *Usecases {
	t.Helper()
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}
	commit := prcheckCommit
	report := "11111111-1111-1111-1111-111111111111"
	f := port.Finding{
		ID: "00000000-0000-0000-0000-000000000021", ProjectID: makeProject(true).ID,
		FindingKind: "sast", Fingerprint: "fp1", CurrentTitle: "XSS in handler",
		CurrentSeverity: "high", CurrentSeverityRank: 3,
		State:                state,
		IntroducedByReportID: &report, IntroducedCommitSha: &commit,
	}
	fr.getByIDFn = func(ctx context.Context, id string) (port.Finding, error) {
		return f, nil
	}
	fr.getDisplayContextFn = func(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
		return port.FindingDisplayContext{ToolName: "semgrep"}, nil
	}
	return New(Deps{Stores: &port.Stores{
		Projects: pr, Reports: rr, Findings: fr,
		Waivers: &mockWaiverRepo{},
	}})
}

func TestPreviewNotification_IssueCreate(t *testing.T) {
	uc := notifyHarness(t, "open")
	out, err := uc.PreviewNotification(
		findingScopeCtx(makeProject(true).ID),
		"00000000-0000-0000-0000-000000000021", "issue", "SEC", false,
	)
	require.NoError(t, err)
	require.True(t, out.Supported)
	require.NotNil(t, out.Plan)
	assert.Equal(t, "create", string(out.Plan.Action))
	assert.Equal(t, "SEC", out.Plan.Target)
	assert.NotEmpty(t, out.Plan.DedupeKey)
}

func TestPreviewNotification_FixedCloses(t *testing.T) {
	uc := notifyHarness(t, "fixed")
	out, err := uc.PreviewNotification(
		findingScopeCtx(makeProject(true).ID),
		"00000000-0000-0000-0000-000000000021", "issue", "SEC", true,
	)
	require.NoError(t, err)
	require.True(t, out.Supported)
	assert.Equal(t, "close", string(out.Plan.Action))
}

func TestPreviewNotification_Message(t *testing.T) {
	uc := notifyHarness(t, "open")
	out, err := uc.PreviewNotification(
		findingScopeCtx(makeProject(true).ID),
		"00000000-0000-0000-0000-000000000021", "message", "#security", false,
	)
	require.NoError(t, err)
	require.True(t, out.Supported)
	assert.Contains(t, out.Plan.Title, "new")
}

func TestPreviewNotification_Refusal(t *testing.T) {
	uc := notifyHarness(t, "open")
	out, err := uc.PreviewNotification(
		findingScopeCtx(makeProject(true).ID),
		"00000000-0000-0000-0000-000000000021", "pager", "SEC", false,
	)
	require.NoError(t, err)
	assert.False(t, out.Supported)
	assert.Nil(t, out.Plan)
}

func TestPreviewNotification_InvalidID(t *testing.T) {
	uc := notifyHarness(t, "open")
	_, err := uc.PreviewNotification(context.Background(), "not-a-uuid", "issue", "SEC", false)
	require.Error(t, err)
}
