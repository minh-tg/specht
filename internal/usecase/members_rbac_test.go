package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

func rbacTestProject() port.Project {
	return port.Project{
		ID:   "00000000-0000-0000-0000-000000000001",
		Slug: "rbac-test",
		Name: "RBAC Test",
	}
}

func projectRoleCtx(userID, role string) context.Context {
	return auth.ContextWithIdentity(context.Background(), &auth.Identity{
		UserID: userID,
		Role:   auth.RoleViewer, // session role is regular user
	})
}

func setupMembersRBACTest() (*Usecases, *mockProjectRepo) {
	pr := &mockProjectRepo{}
	p := rbacTestProject()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		if slug == p.Slug {
			return p, nil
		}
		return port.Project{}, port.ErrNotFound
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	return uc, pr
}

func TestAddProjectMember_DelegationCeiling(t *testing.T) {
	uc, pr := setupMembersRBACTest()

	// Manager caller
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		if userID == "mgr-1" {
			return auth.RoleManager, nil
		}
		return "", port.ErrNotFound
	}

	pr.upsertMemberFn = func(ctx context.Context, projectID, userID, role string) (port.ProjectMember, error) {
		return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: role, CreatedAt: time.Now()}, nil
	}

	// 1. Manager can add a Member
	m, err := uc.AddProjectMember(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", "00000000-0000-4000-8000-000000000001", auth.RoleMember)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleMember, m.Role)

	// 2. Manager can add another Manager
	m, err = uc.AddProjectMember(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", "00000000-0000-4000-8000-000000000002", auth.RoleManager)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleManager, m.Role)

	// 3. Manager CANNOT add an Admin (Delegation Ceiling)
	_, err = uc.AddProjectMember(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", "00000000-0000-4000-8000-000000000003", auth.RoleAdmin)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	// 4. Regular Member CANNOT add anyone
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		return auth.RoleMember, nil
	}
	_, err = uc.AddProjectMember(projectRoleCtx("00000000-0000-4000-8000-000000000001", auth.RoleMember), "rbac-test", "00000000-0000-4000-8000-000000000004", auth.RoleMember)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestAddProjectMember_PeerProtection(t *testing.T) {
	uc, pr := setupMembersRBACTest()

	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		if userID == "mgr-1" {
			return auth.RoleManager, nil
		}
		if userID == "00000000-0000-4000-8000-000000000007" {
			return auth.RoleAdmin, nil
		}
		return "", port.ErrNotFound
	}

	pr.getMemberFn = func(ctx context.Context, projectID, userID string) (port.ProjectMember, error) {
		if userID == "00000000-0000-4000-8000-000000000005" {
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleManager}, nil
		}
		if userID == "00000000-0000-4000-8000-000000000006" {
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleAdmin}, nil
		}
		return port.ProjectMember{}, port.ErrNotFound
	}

	// Manager CANNOT demote a fellow Manager
	_, err := uc.AddProjectMember(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", "00000000-0000-4000-8000-000000000005", auth.RoleMember)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	// Manager CANNOT modify an Admin
	_, err = uc.AddProjectMember(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", "00000000-0000-4000-8000-000000000006", auth.RoleMember)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	// Admin CAN modify a Manager
	pr.upsertMemberFn = func(ctx context.Context, projectID, userID, role string) (port.ProjectMember, error) {
		return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: role}, nil
	}
	m, err := uc.AddProjectMember(projectRoleCtx("00000000-0000-4000-8000-000000000007", auth.RoleAdmin), "rbac-test", "00000000-0000-4000-8000-000000000005", auth.RoleMember)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleMember, m.Role)
}

func TestAddProjectMember_LastAdminInvariant(t *testing.T) {
	uc, pr := setupMembersRBACTest()

	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		return auth.RoleAdmin, nil
	}

	pr.getMemberFn = func(ctx context.Context, projectID, userID string) (port.ProjectMember, error) {
		return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleAdmin}, nil
	}

	// Only 1 admin remains
	pr.countAdminsFn = func(ctx context.Context, projectID string) (int, error) {
		return 1, nil
	}

	// Demoting the last admin must fail
	_, err := uc.AddProjectMember(projectRoleCtx("00000000-0000-4000-8000-000000000007", auth.RoleAdmin), "rbac-test", "00000000-0000-4000-8000-000000000007", auth.RoleMember)
	assert.ErrorIs(t, err, ErrLastAdminForbidden)

	// If 2 admins exist, demotion succeeds
	pr.countAdminsFn = func(ctx context.Context, projectID string) (int, error) {
		return 2, nil
	}
	pr.upsertMemberFn = func(ctx context.Context, projectID, userID, role string) (port.ProjectMember, error) {
		return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: role}, nil
	}
	m, err := uc.AddProjectMember(projectRoleCtx("00000000-0000-4000-8000-000000000007", auth.RoleAdmin), "rbac-test", "00000000-0000-4000-8000-000000000007", auth.RoleMember)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleMember, m.Role)
}

func TestRemoveProjectMember_SelfExitAndLastAdmin(t *testing.T) {
	uc, pr := setupMembersRBACTest()

	// 1. Member can leave
	pr.getMemberFn = func(ctx context.Context, projectID, userID string) (port.ProjectMember, error) {
		if userID == "00000000-0000-4000-8000-000000000001" {
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleMember}, nil
		}
		if userID == "00000000-0000-4000-8000-000000000008" {
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleAdmin}, nil
		}
		return port.ProjectMember{}, port.ErrNotFound
	}
	pr.deleteMemberFn = func(ctx context.Context, projectID, userID string) error {
		return nil
	}

	err := uc.RemoveProjectMember(projectRoleCtx("00000000-0000-4000-8000-000000000001", auth.RoleMember), "rbac-test", "00000000-0000-4000-8000-000000000001")
	require.NoError(t, err)

	// 2. Sole admin cannot leave
	pr.countAdminsFn = func(ctx context.Context, projectID string) (int, error) {
		return 1, nil
	}
	err = uc.RemoveProjectMember(projectRoleCtx("00000000-0000-4000-8000-000000000008", auth.RoleAdmin), "rbac-test", "00000000-0000-4000-8000-000000000008")
	assert.ErrorIs(t, err, ErrLastAdminForbidden)

	// 3. Admin can leave if another admin exists
	pr.countAdminsFn = func(ctx context.Context, projectID string) (int, error) {
		return 2, nil
	}
	err = uc.RemoveProjectMember(projectRoleCtx("00000000-0000-4000-8000-000000000008", auth.RoleAdmin), "rbac-test", "00000000-0000-4000-8000-000000000008")
	require.NoError(t, err)
}

func TestMemberWrites_LostLastAdminRaceIsReportedAsLastAdmin(t *testing.T) {
	uc, pr := setupMembersRBACTest()
	pr.getMemberFn = func(ctx context.Context, projectID, userID string) (port.ProjectMember, error) {
		return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleAdmin}, nil
	}
	// The pre-check sees a second admin, but another request removes it before
	// this write runs, so the store refuses under its project lock.
	pr.countAdminsFn = func(ctx context.Context, projectID string) (int, error) {
		return 2, nil
	}
	pr.deleteMemberFn = func(ctx context.Context, projectID, userID string) error {
		return port.ErrLastAdmin
	}
	pr.upsertMemberFn = func(ctx context.Context, projectID, userID, role string) (port.ProjectMember, error) {
		return port.ProjectMember{}, port.ErrLastAdmin
	}
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		return auth.RoleAdmin, nil
	}
	admin := projectRoleCtx("00000000-0000-4000-8000-000000000007", auth.RoleAdmin)

	err := uc.RemoveProjectMember(admin, "rbac-test", "00000000-0000-4000-8000-000000000007")
	assert.ErrorIs(t, err, ErrLastAdminForbidden)

	_, err = uc.AddProjectMember(admin, "rbac-test", "00000000-0000-4000-8000-000000000007", auth.RoleMember)
	assert.ErrorIs(t, err, ErrLastAdminForbidden)
}

func TestRemoveProjectMember_PeerProtection(t *testing.T) {
	uc, pr := setupMembersRBACTest()

	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		if userID == "mgr-1" {
			return auth.RoleManager, nil
		}
		return "", port.ErrNotFound
	}
	pr.getMemberFn = func(ctx context.Context, projectID, userID string) (port.ProjectMember, error) {
		if userID == "00000000-0000-4000-8000-000000000009" {
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleMember}, nil
		}
		if userID == "00000000-0000-4000-8000-000000000010" {
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleManager}, nil
		}
		if userID == "00000000-0000-4000-8000-000000000011" {
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleAdmin}, nil
		}
		return port.ProjectMember{}, port.ErrNotFound
	}
	pr.deleteMemberFn = func(ctx context.Context, projectID, userID string) error {
		return nil
	}

	// Manager can remove Member
	err := uc.RemoveProjectMember(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", "00000000-0000-4000-8000-000000000009")
	require.NoError(t, err)

	// Manager CANNOT remove fellow Manager
	err = uc.RemoveProjectMember(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", "00000000-0000-4000-8000-000000000010")
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	// Manager CANNOT remove Admin
	err = uc.RemoveProjectMember(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", "00000000-0000-4000-8000-000000000011")
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}
