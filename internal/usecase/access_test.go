package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/port"
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
