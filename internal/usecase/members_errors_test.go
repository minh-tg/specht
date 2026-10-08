package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

const (
	errTestAdmin  = "00000000-0000-4000-8000-0000000000a1"
	errTestTarget = "00000000-0000-4000-8000-0000000000a2"
)

func setupMemberErrorsTest() (*Usecases, *mockProjectRepo) {
	uc, pr := setupMembersRBACTest()
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		return auth.RoleAdmin, nil
	}
	return uc, pr
}

func TestAddProjectMember_MalformedUserIDIsRejected(t *testing.T) {
	uc, _ := setupMemberErrorsTest()
	_, err := uc.AddProjectMember(projectRoleCtx(errTestAdmin, auth.RoleAdmin), "rbac-test", "not-a-uuid", auth.RoleMember)
	assert.ErrorIs(t, err, ErrInvalidID, "the store would otherwise fail to parse it and report a server error")
}

func TestRemoveProjectMember_MalformedUserIDIsRejected(t *testing.T) {
	uc, _ := setupMemberErrorsTest()
	err := uc.RemoveProjectMember(projectRoleCtx(errTestAdmin, auth.RoleAdmin), "rbac-test", "not-a-uuid")
	assert.ErrorIs(t, err, ErrInvalidID)
}

func TestAddProjectMember_InvalidRoleIsATypedError(t *testing.T) {
	uc, _ := setupMemberErrorsTest()
	_, err := uc.AddProjectMember(projectRoleCtx(errTestAdmin, auth.RoleAdmin), "rbac-test", errTestTarget, "superuser")
	assert.ErrorIs(t, err, ErrInvalidMemberRole)
}

func TestAddProjectMember_UnknownUserIsReported(t *testing.T) {
	uc, pr := setupMemberErrorsTest()
	pr.getMemberFn = func(ctx context.Context, projectID, userID string) (port.ProjectMember, error) {
		return port.ProjectMember{}, port.ErrNotFound
	}
	pr.upsertMemberFn = func(ctx context.Context, projectID, userID, role string) (port.ProjectMember, error) {
		return port.ProjectMember{}, port.ErrNotFound
	}
	_, err := uc.AddProjectMember(projectRoleCtx(errTestAdmin, auth.RoleAdmin), "rbac-test", errTestTarget, auth.RoleMember)
	assert.ErrorIs(t, err, ErrMemberUserNotFound)
}

func TestMemberWrites_UnknownProjectLooksLikeNoAccess(t *testing.T) {
	uc, _ := setupMemberErrorsTest()
	admin := projectRoleCtx(errTestAdmin, auth.RoleAdmin)

	_, err := uc.AddProjectMember(admin, "no-such-project", errTestTarget, auth.RoleMember)
	assert.ErrorIs(t, err, ErrProjectAccessDenied, "a missing project must not be distinguishable from one the caller cannot see")

	err = uc.RemoveProjectMember(admin, "no-such-project", errTestTarget)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}
