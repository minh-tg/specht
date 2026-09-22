package usecase

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

func policyHarness() (*Usecases, *mockProjectRepo, *mockPolicyRepo) {
	pr, _, _ := makeTestRepos()
	py := &mockPolicyRepo{}
	uc := New(Deps{Stores: &port.Stores{Projects: pr, Policy: py}})
	return uc, pr, py
}

func adminCtx() context.Context {
	return auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "00000000-0000-0000-0000-000000000040",
		Role:   auth.RoleAdmin,
	})
}

func TestCreatePolicyTemplate_Validates(t *testing.T) {
	uc, _, py := policyHarness()
	py.getByNameFn = func(ctx context.Context, name string) (port.PolicyTemplate, error) {
		return port.PolicyTemplate{}, port.ErrNotFound
	}
	py.createFn = func(ctx context.Context, input port.PolicyTemplateInput) (port.PolicyTemplate, error) {
		return port.PolicyTemplate{ID: "t1", Name: input.Name, Version: 1}, nil
	}

	out, err := uc.CreatePolicyTemplate(context.Background(), "strict", "d", json.RawMessage(`{"severity_floor":"critical"}`))
	require.NoError(t, err)
	assert.Equal(t, "strict", out.Name)
	assert.Equal(t, "critical", out.Definition["severity_floor"])

	_, err = uc.CreatePolicyTemplate(context.Background(), "bad", "d", json.RawMessage(`{"severity_floor":"extreme"}`))
	require.Error(t, err)

	_, err = uc.CreatePolicyTemplate(context.Background(), "  ", "d", json.RawMessage(`{}`))
	require.Error(t, err)
}

func TestCreatePolicyTemplate_Conflict(t *testing.T) {
	uc, _, py := policyHarness()
	py.getByNameFn = func(ctx context.Context, name string) (port.PolicyTemplate, error) {
		return port.PolicyTemplate{ID: "t0", Name: name}, nil
	}

	_, err := uc.CreatePolicyTemplate(context.Background(), "strict", "d", json.RawMessage(`{}`))
	assert.ErrorIs(t, err, ErrPolicyConflict)
}

func TestUpdatePolicyTemplate_NotFound(t *testing.T) {
	uc, _, py := policyHarness()
	py.getByIDFn = func(ctx context.Context, id string) (port.PolicyTemplate, error) {
		return port.PolicyTemplate{}, port.ErrNotFound
	}

	_, err := uc.UpdatePolicyTemplate(context.Background(), "11111111-1111-1111-1111-111111111111", "x", "d", json.RawMessage(`{}`))
	assert.ErrorIs(t, err, ErrPolicyNotFound)
}

func TestPolicyIDs_InvalidUUIDRejected(t *testing.T) {
	uc, _, _ := policyHarness()

	_, err := uc.UpdatePolicyTemplate(context.Background(), "not-a-uuid", "x", "d", json.RawMessage(`{}`))
	assert.ErrorIs(t, err, ErrInvalidID)

	assert.ErrorIs(t, uc.DeletePolicyTemplate(context.Background(), "not-a-uuid"), ErrInvalidID)
}

func TestSetProjectPolicy_AssignsAndResolves(t *testing.T) {
	uc, pr, py := policyHarness()
	project := makeProject(true)
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return project, nil
	}
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return nil, nil
	}
	py.getByNameFn = func(ctx context.Context, name string) (port.PolicyTemplate, error) {
		return port.PolicyTemplate{
			ID: "t1", Name: "strict", Version: 2,
			Definition: json.RawMessage(`{"severity_floor":"critical"}`),
		}, nil
	}
	py.setProjectFn = func(ctx context.Context, projectID string, templateID *string) (port.Project, error) {
		require.NotNil(t, templateID)
		assert.Equal(t, "t1", *templateID)
		updated := project
		updated.PolicyTemplateID = templateID
		return updated, nil
	}
	py.getByIDFn = func(ctx context.Context, id string) (port.PolicyTemplate, error) {
		return port.PolicyTemplate{
			ID: "t1", Name: "strict", Version: 2,
			Definition: json.RawMessage(`{"severity_floor":"critical"}`),
		}, nil
	}

	out, err := uc.SetProjectPolicy(adminCtx(), "my-app", "strict")
	require.NoError(t, err)
	assert.Equal(t, "critical", out.SeverityFloor)
	assert.Equal(t, "template", out.SeveritySource)
	require.NotNil(t, out.TemplateName)
	assert.Equal(t, "strict", *out.TemplateName)
}

func TestSetProjectPolicy_OverridesWin(t *testing.T) {
	uc, pr, py := policyHarness()
	project := makeProject(true)
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return project, nil
	}
	pr.updateSettingsFn = func(ctx context.Context, projectID string, settings json.RawMessage) (port.Project, error) {
		updated := project
		updated.Settings = settings
		return updated, nil
	}
	py.getByIDFn = func(ctx context.Context, id string) (port.PolicyTemplate, error) {
		return port.PolicyTemplate{}, port.ErrNotFound
	}

	out, err := uc.SetProjectPolicyOverrides(adminCtx(), "my-app", map[string]string{"severity_floor": "low"})
	require.NoError(t, err)
	assert.Equal(t, "low", out.SeverityFloor)
	assert.Equal(t, "override", out.SeveritySource)
	assert.Nil(t, out.TemplateName)

	_, err = uc.SetProjectPolicyOverrides(adminCtx(), "my-app", map[string]string{"severity_floor": "bogus"})
	require.Error(t, err)
}

func TestEffectivePolicy_DeniedForNonAdmin(t *testing.T) {
	uc, pr, _ := policyHarness()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return makeProject(true), nil
	}

	_, err := uc.SetProjectPolicy(context.Background(), "my-app", "strict")
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestGetGateStatus_UsesPolicyFloor(t *testing.T) {
	pr, _, fr := makeTestRepos()
	project := makeProject(true)
	project.Settings = json.RawMessage(`{"policy":{"severity_floor":"critical"}}`)
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return project, nil
	}
	fr.listGateCandidatesFn = func(ctx context.Context, projectID string, minRank int16) ([]port.GateCandidate, error) {
		assert.Equal(t, int16(4), minRank, "policy floor critical must reach the gate")
		// Mirror the SQL prefilter (rank >= floor): below-floor findings
		// never reach evaluation.
		if minRank > 3 {
			return nil, nil
		}
		return []port.GateCandidate{{
			Finding: port.Finding{
				ID: "00000000-0000-0000-0000-000000000099", ProjectID: project.ID,
				CurrentSeverityRank: 3, FindingKind: "sca", Fingerprint: "fp-debt",
				CurrentTitle: "CVE-2023-0001", AnalysisState: "unanalyzed",
			},
		}}, nil
	}
	uc := New(Deps{Stores: &port.Stores{
		Projects: pr, Findings: fr, Waivers: &mockWaiverRepo{},
	}})

	out, err := uc.GetGateStatus(context.Background(), "my-app", 0)
	require.NoError(t, err)
	assert.False(t, out.ThresholdBreached, "high finding must not breach a critical floor")
	require.NotNil(t, out.Policy)
	assert.Equal(t, "critical", out.Policy.SeverityFloor)
	assert.Equal(t, "override", out.Policy.SeveritySource)
}
