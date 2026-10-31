package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const (
	scopeOwnFinding   = "00000000-0000-0000-0000-0000000000f1"
	scopeForeignFind  = "00000000-0000-0000-0000-0000000000f2"
	scopeMissingFind  = "00000000-0000-0000-0000-0000000000f3"
	scopeOwnEnv       = "00000000-0000-0000-0000-0000000000e1"
	scopeOwnTarget    = "00000000-0000-0000-0000-0000000000c1"
	scopeOwnArtifact  = "00000000-0000-0000-0000-0000000000d1"
	scopeUnknownID    = "00000000-0000-0000-0000-0000000000ff"
	scopeWaiverID     = "00000000-0000-0000-0000-0000000000b1"
	scopeOtherProject = "other-project"
)

// waiverScopeUsecase wires stores in which only the ids above exist in the
// project. The environment, target and artifact stores answer ErrNotFound for
// every other id, as their project-scoped GetByID does for a missing id and for
// an id of another project alike.
func waiverScopeUsecase(t *testing.T, wr *mockWaiverRepo) *Usecases {
	t.Helper()
	project := makeProject(true)
	projects := &mockProjectRepo{
		getBySlugFn:     func(context.Context, string) (port.Project, error) { return project, nil },
		effectiveRoleFn: func(context.Context, string, string) (string, error) { return auth.RoleAdmin, nil },
	}
	findings := &mockFindingRepo{
		getByIDFn: func(_ context.Context, id string) (port.Finding, error) {
			switch id {
			case scopeOwnFinding:
				return port.Finding{ID: id, ProjectID: project.ID}, nil
			case scopeForeignFind:
				return port.Finding{ID: id, ProjectID: scopeOtherProject}, nil
			}
			return port.Finding{}, port.ErrNotFound
		},
	}
	environments := &mockEnvironmentRepo{getByIDFn: func(_ context.Context, id, projectID string) (port.Environment, error) {
		if id == scopeOwnEnv && projectID == project.ID {
			return port.Environment{ID: id}, nil
		}
		return port.Environment{}, port.ErrNotFound
	}}
	targets := &mockTargetRepo{getByIDFn: func(_ context.Context, id, projectID string) (port.Target, error) {
		if id == scopeOwnTarget && projectID == project.ID {
			return port.Target{ID: id}, nil
		}
		return port.Target{}, port.ErrNotFound
	}}
	artifacts := &mockArtifactRepo{getByIDFn: func(_ context.Context, id, projectID string) (port.Artifact, error) {
		if id == scopeOwnArtifact && projectID == project.ID {
			return port.Artifact{ID: id}, nil
		}
		return port.Artifact{}, port.ErrNotFound
	}}
	return New(Deps{Stores: &port.Stores{
		Projects: projects, Waivers: wr, Findings: findings,
		Environments: environments, Targets: targets, Artifacts: artifacts,
	}})
}

// scopeCases are the scope inputs a waiver must refuse. A foreign id and a
// missing id give the same error, so the answer does not say which exists.
func scopeCases() map[string]struct {
	targets  []string
	contexts []CreateWaiverContextInput
} {
	return map[string]struct {
		targets  []string
		contexts []CreateWaiverContextInput
	}{
		"foreign finding":     {targets: []string{scopeForeignFind}},
		"missing finding":     {targets: []string{scopeMissingFind}},
		"own and foreign":     {targets: []string{scopeOwnFinding, scopeForeignFind}},
		"foreign environment": {contexts: []CreateWaiverContextInput{{EnvironmentID: scopeUnknownID}}},
		"foreign target":      {contexts: []CreateWaiverContextInput{{TargetID: scopeUnknownID}}},
		"foreign artifact":    {contexts: []CreateWaiverContextInput{{ArtifactID: scopeUnknownID}}},
		"own and foreign ctx": {contexts: []CreateWaiverContextInput{{EnvironmentID: scopeOwnEnv}, {EnvironmentID: scopeUnknownID}}},
	}
}

func TestCreateWaiverRefusesFindingsAndScopesOutsideTheProject(t *testing.T) {
	for name, tc := range scopeCases() {
		t.Run(name, func(t *testing.T) {
			wr := &mockWaiverRepo{} // a store call would fail the test
			_, err := waiverScopeUsecase(t, wr).CreateWaiver(sessionCtx("admin", auth.RoleAdmin), CreateWaiverInput{
				ProjectSlug: "my-app", Name: "w", TargetIDs: tc.targets, Contexts: tc.contexts,
			})
			require.ErrorIs(t, err, ErrWaiverScopeNotFound)
		})
	}
}

func TestUpdateWaiverRefusesFindingsAndScopesOutsideTheProject(t *testing.T) {
	for name, tc := range scopeCases() {
		t.Run(name, func(t *testing.T) {
			wr := &mockWaiverRepo{getByIDFn: waiverExists}
			_, err := waiverScopeUsecase(t, wr).UpdateWaiver(sessionCtx("admin", auth.RoleAdmin), UpdateWaiverInput{
				ProjectSlug: "my-app", WaiverID: scopeWaiverID, TargetIDs: tc.targets, Contexts: tc.contexts,
			})
			require.ErrorIs(t, err, ErrWaiverScopeNotFound)
		})
	}
}

func TestWaiverScopeErrorsAreTheSameForForeignAndMissingIDs(t *testing.T) {
	uc := waiverScopeUsecase(t, &mockWaiverRepo{})
	admin := sessionCtx("admin", auth.RoleAdmin)
	create := func(id string) error {
		_, err := uc.CreateWaiver(admin, CreateWaiverInput{ProjectSlug: "my-app", Name: "w", TargetIDs: []string{id}})
		return err
	}
	foreign, missing := create(scopeForeignFind), create(scopeMissingFind)
	require.Error(t, foreign)
	require.Error(t, missing)
	assert.Equal(t, "finding not found in this project", foreign.Error())
	assert.Equal(t, foreign.Error(), missing.Error())
}

func TestCreateWaiverAcceptsScopesInsideTheProject(t *testing.T) {
	var got port.CreateWaiverInput
	wr := &mockWaiverRepo{createWithDetailsFn: func(_ context.Context, in port.CreateWaiverInput) (port.Waiver, error) {
		got = in
		return port.Waiver{ID: scopeWaiverID, ProjectID: in.ProjectID, Name: in.Name}, nil
	}}
	_, err := waiverScopeUsecase(t, wr).CreateWaiver(sessionCtx("admin", auth.RoleAdmin), CreateWaiverInput{
		ProjectSlug: "my-app", Name: "w",
		TargetIDs: []string{scopeOwnFinding, scopeOwnFinding},
		Contexts:  []CreateWaiverContextInput{{EnvironmentID: scopeOwnEnv, TargetID: scopeOwnTarget, ArtifactID: scopeOwnArtifact}},
	})
	require.NoError(t, err)
	assert.Len(t, got.Targets, 2)
	assert.Len(t, got.Contexts, 1)
}

// An id that is not a UUID is the caller's mistake: a 400, not a server error.
func TestWaiverScopeWithAMalformedIDIsAnInvalidRequest(t *testing.T) {
	uc := waiverScopeUsecase(t, &mockWaiverRepo{getByIDFn: waiverExists})
	admin := sessionCtx("admin", auth.RoleAdmin)
	_, err := uc.CreateWaiver(admin, CreateWaiverInput{ProjectSlug: "my-app", Name: "w", TargetIDs: []string{"nope"}})
	require.ErrorIs(t, err, ErrInvalidWaiverRequest)
	_, err = uc.CreateWaiver(admin, CreateWaiverInput{
		ProjectSlug: "my-app", Name: "w", Contexts: []CreateWaiverContextInput{{EnvironmentID: "nope"}},
	})
	require.ErrorIs(t, err, ErrInvalidWaiverRequest)
	_, err = uc.UpdateWaiver(admin, UpdateWaiverInput{
		ProjectSlug: "my-app", WaiverID: scopeWaiverID, TargetIDs: []string{"nope"},
	})
	require.ErrorIs(t, err, ErrInvalidWaiverRequest)
}
