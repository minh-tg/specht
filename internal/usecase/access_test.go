package usecase

import (
	"context"
	"testing"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
)

// findingScopeCtx returns a context carrying an authenticated session-user
// identity for tests exercising finding-scoped paths. Membership itself is
// provided by the mock project store (makeTestRepos defaults IsMember to
// allow); use memberUsecases or explicit isMemberFn overrides for denial
// cases.
func findingScopeCtx(projectID string) context.Context {
	return auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID:    "00000000-0000-0000-0000-000000000040",
		ProjectID: projectID,
		Role:      auth.RoleViewer,
	})
}

// findingFixtureProjectID is the project that makeFindingRow/makeFinding rows
// belong to (see makeFindingRow in usecase_test.go).
const findingFixtureProjectID = "00000000-0000-0000-0000-000000000001"

// memberUsecases returns a Usecases whose project store reports membership
// per the members map (projectID -> member userIDs).
func memberUsecases(members map[string]bool) *Usecases {
	pr := &mockProjectRepo{}
	pr.isMemberFn = func(ctx context.Context, projectID, userID string) (bool, error) {
		return members[projectID+"/"+userID], nil
	}
	return New(Deps{Stores: &port.Stores{Projects: pr}})
}

func sessionCtx(userID, role string) context.Context {
	return auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: userID,
		Role:   role,
	})
}

func apiKeyCtx(userID, projectID string) context.Context {
	return auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID:    userID,
		ProjectID: projectID,
		Scopes:    []string{auth.ScopeRead, auth.ScopeAdmin},
		IsAPIKey:  true,
	})
}

func TestCheckFindingProjectIDAccess_MemberAllowed(t *testing.T) {
	uc := memberUsecases(map[string]bool{findingFixtureProjectID + "/u1": true})
	err := uc.checkFindingProjectIDAccess(sessionCtx("u1", auth.RoleViewer), findingFixtureProjectID)
	assert.NoError(t, err)
}

func TestCheckFindingProjectIDAccess_NonMemberDenied(t *testing.T) {
	uc := memberUsecases(map[string]bool{})
	err := uc.checkFindingProjectIDAccess(sessionCtx("u1", auth.RoleViewer), findingFixtureProjectID)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestCheckFindingProjectIDAccess_GlobalAdminBypassesMembership(t *testing.T) {
	uc := memberUsecases(map[string]bool{})
	err := uc.checkFindingProjectIDAccess(sessionCtx("admin-1", auth.RoleAdmin), findingFixtureProjectID)
	assert.NoError(t, err)
}

func TestCheckFindingProjectIDAccess_APIKeyInProjectAllowed(t *testing.T) {
	uc := memberUsecases(map[string]bool{})
	assert.NoError(t, uc.checkFindingProjectIDAccess(apiKeyCtx("key-1", findingFixtureProjectID), findingFixtureProjectID))
}

func TestCheckFindingProjectIDAccess_APIKeyCrossProjectDenied(t *testing.T) {
	uc := memberUsecases(map[string]bool{})
	err := uc.checkFindingProjectIDAccess(apiKeyCtx("key-1", "00000000-0000-0000-0000-000000000099"), findingFixtureProjectID)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

// Regression: a nil context identity must not bypass the project check.
func TestCheckFindingProjectIDAccess_NoIdentityDenied(t *testing.T) {
	uc := memberUsecases(map[string]bool{})
	err := uc.checkFindingProjectIDAccess(context.Background(), findingFixtureProjectID)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestCheckFindingRowsProjectAccess_NonMemberDenied(t *testing.T) {
	uc := memberUsecases(map[string]bool{})
	err := uc.checkFindingRowsProjectAccess(
		sessionCtx("u1", auth.RoleViewer),
		[]port.Finding{makeFindingRow(1)},
	)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestCheckFindingRowsProjectAccess_NoIdentityDenied(t *testing.T) {
	uc := memberUsecases(map[string]bool{})
	err := uc.checkFindingRowsProjectAccess(context.Background(), []port.Finding{makeFindingRow(1)})
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestRequireProjectManager_UsesEffectiveProjectRole(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		return auth.RoleViewer, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	assert.ErrorIs(t, uc.requireProjectManager(sessionCtx("u1", auth.RoleViewer), findingFixtureProjectID), ErrProjectAccessDenied)

	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		return auth.RoleEditor, nil
	}
	assert.NoError(t, uc.requireProjectManager(sessionCtx("u1", auth.RoleViewer), findingFixtureProjectID))
}

func TestRequireProjectIngest_RequiresEditorRoleOrIngestScope(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		return auth.RoleViewer, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	assert.ErrorIs(t, uc.requireProjectIngest(sessionCtx("u1", auth.RoleViewer), findingFixtureProjectID), ErrProjectAccessDenied)

	ingestKey := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "key-1", ProjectID: findingFixtureProjectID, IsAPIKey: true,
		Scopes: []string{auth.ScopeIngest},
	})
	assert.NoError(t, uc.requireProjectIngest(ingestKey, findingFixtureProjectID))
	assert.ErrorIs(t, uc.requireProjectIngest(apiKeyCtx("key-1", findingFixtureProjectID), findingFixtureProjectID), ErrProjectAccessDenied)
}

func TestRequireProjectAdminForWaiver_EnforcesRoleAndKeyScope(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		return auth.RoleEditor, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	assert.ErrorIs(t, uc.requireProjectAdminForWaiver(sessionCtx("u1", auth.RoleEditor), findingFixtureProjectID), ErrProjectAccessDenied)

	adminKey := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "key-1", ProjectID: findingFixtureProjectID, IsAPIKey: true,
		Scopes: []string{auth.ScopeAdmin},
	})
	assert.NoError(t, uc.requireProjectAdminForWaiver(adminKey, findingFixtureProjectID))

	readKey := auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: "key-1", ProjectID: findingFixtureProjectID, IsAPIKey: true,
		Scopes: []string{auth.ScopeRead},
	})
	assert.ErrorIs(t, uc.requireProjectAdminForWaiver(readKey, findingFixtureProjectID), ErrProjectAccessDenied)
	assert.ErrorIs(t, uc.requireProjectAdminForWaiver(apiKeyCtx("key-1", "other-project"), findingFixtureProjectID), ErrProjectAccessDenied)
}

func TestCheckFindingRowsProjectAccess_DeduplicatesProjectChecks(t *testing.T) {
	pr := &mockProjectRepo{}
	queryCount := 0
	pr.isMemberEffectiveFn = func(ctx context.Context, projectID, userID string) (bool, error) {
		queryCount++
		return true, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})

	// 10 findings belonging to 2 unique projects
	findings := []port.Finding{
		{ID: "f1", ProjectID: "p1"},
		{ID: "f2", ProjectID: "p1"},
		{ID: "f3", ProjectID: "p1"},
		{ID: "f4", ProjectID: "p2"},
		{ID: "f5", ProjectID: "p2"},
		{ID: "f6", ProjectID: "p1"},
	}

	err := uc.checkFindingRowsProjectAccess(sessionCtx("u1", auth.RoleViewer), findings)
	assert.NoError(t, err)
	assert.Equal(t, 2, queryCount, "must only query membership once per unique project ID")
}
