package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

const (
	gateOwnReportID     = "00000000-0000-0000-0000-000000000097"
	gateForeignReportID = "00000000-0000-0000-0000-000000000098"
	gateForeignProject  = "00000000-0000-0000-0000-000000000002"
)

// stubReportOwnedBy makes a report store answer any id with a report of the
// given project, so tests of the introduced-only gate reach the evaluation.
func stubReportOwnedBy(rr *mockReportRepo, projectID string) {
	rr.getByIDFn = func(_ context.Context, id string) (port.Report, error) {
		return port.Report{ID: id, ProjectID: projectID}, nil
	}
}

// TestGetIntroducedGateStatus_ForeignReportDenied covers the gate endpoint
// scoped to another tenant's report: a member of X who passes Y's report id
// must be refused before any finding of Y is evaluated.
func TestGetIntroducedGateStatus_ForeignReportDenied(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(context.Context, string) (port.Project, error) {
		return makeProject(true), nil
	}
	rr.getByIDFn = func(_ context.Context, id string) (port.Report, error) {
		return port.Report{ID: id, ProjectID: gateForeignProject}, nil
	}
	var introducedLookups int
	fr.listIntroducedGateCandidatesFn = func(context.Context, string, string, int16) ([]port.GateCandidate, error) {
		introducedLookups++
		return nil, nil
	}
	uc := New(Deps{Stores: &port.Stores{
		Projects: pr, Reports: rr, Findings: fr, Waivers: &mockWaiverRepo{},
	}})

	_, err := uc.GetIntroducedGateStatus(adminCtx(), "my-app", 0, gateForeignReportID)
	require.ErrorIs(t, err, ErrProjectAccessDenied)
	assert.Zero(t, introducedLookups, "a foreign report must never be evaluated")
}

// TestGetIntroducedGateStatus_MissingReportDenied pins that a report id that
// does not exist answers exactly like a foreign one, so ids cannot be probed.
func TestGetIntroducedGateStatus_MissingReportDenied(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	pr.getBySlugFn = func(context.Context, string) (port.Project, error) {
		return makeProject(true), nil
	}
	rr.getByIDFn = func(context.Context, string) (port.Report, error) {
		return port.Report{}, port.ErrNotFound
	}
	var introducedLookups int
	fr.listIntroducedGateCandidatesFn = func(context.Context, string, string, int16) ([]port.GateCandidate, error) {
		introducedLookups++
		return nil, nil
	}
	uc := New(Deps{Stores: &port.Stores{
		Projects: pr, Reports: rr, Findings: fr, Waivers: &mockWaiverRepo{},
	}})

	_, err := uc.GetIntroducedGateStatus(adminCtx(), "my-app", 0, gateForeignReportID)
	require.ErrorIs(t, err, ErrProjectAccessDenied)
	assert.Zero(t, introducedLookups, "a missing report must never be evaluated")
}

// TestGetIntroducedGateStatus_OwnReportEvaluates keeps the happy path: the
// project's own report still reaches the introduced-only evaluation.
func TestGetIntroducedGateStatus_OwnReportEvaluates(t *testing.T) {
	pr, rr, fr := makeTestRepos()
	project := makeProject(true)
	pr.getBySlugFn = func(context.Context, string) (port.Project, error) {
		return project, nil
	}
	rr.getByIDFn = func(_ context.Context, id string) (port.Report, error) {
		return port.Report{ID: id, ProjectID: project.ID}, nil
	}
	var gotReport string
	fr.listIntroducedGateCandidatesFn = func(_ context.Context, projectID, reportID string, minRank int16) ([]port.GateCandidate, error) {
		gotReport = reportID
		return []port.GateCandidate{{
			Finding: port.Finding{
				ID: "00000000-0000-0000-0000-000000000099", ProjectID: project.ID,
				CurrentSeverityRank: 4, FindingKind: "sca", Fingerprint: "fp-introduced",
				CurrentTitle: "CVE-2024-0002", AnalysisState: "unanalyzed",
			},
		}}, nil
	}
	uc := New(Deps{Stores: &port.Stores{
		Projects: pr, Reports: rr, Findings: fr, Waivers: &mockWaiverRepo{},
	}})

	out, err := uc.GetIntroducedGateStatus(adminCtx(), "my-app", 0, gateOwnReportID)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, gateOwnReportID, gotReport)
	assert.True(t, out.ThresholdBreached)
}
