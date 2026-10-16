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

	pr.getMemberFn = func(ctx context.Context, projectID, userID string) (port.ProjectMember, error) {
		if userID == "mgr-1" {
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleManager}, nil
		}
		return port.ProjectMember{}, port.ErrNotFound
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

// A caller whose manager or admin rank comes only from a team link has no
// direct row to vouch for it, so it may hand out nothing above member. A direct
// row is the ceiling even when a team link lifts the caller's effective role.
func TestAddProjectMember_TeamOnlyCallerIsCappedAtMember(t *testing.T) {
	uc, pr := setupMembersRBACTest()
	pr.effectiveRoleFn = func(context.Context, string, string) (string, error) { return auth.RoleAdmin, nil }
	const caller = "00000000-0000-4000-8000-0000000000c1"
	direct := ""
	pr.getMemberFn = func(_ context.Context, projectID, userID string) (port.ProjectMember, error) {
		if userID == caller && direct != "" {
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: direct}, nil
		}
		return port.ProjectMember{}, port.ErrNotFound
	}
	written := 0
	pr.upsertMemberFn = func(_ context.Context, projectID, userID, role string) (port.ProjectMember, error) {
		written++
		return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: role, CreatedAt: time.Now()}, nil
	}
	ctx := projectRoleCtx(caller, auth.RoleViewer)
	const other = "00000000-0000-4000-8000-000000000009"

	for _, role := range []string{auth.RoleAdmin, auth.RoleManager} {
		_, err := uc.AddProjectMember(ctx, "rbac-test", caller, role)
		assert.ErrorIs(t, err, ErrProjectAccessDenied, "self as %s through a team link", role)
		_, err = uc.AddProjectMember(ctx, "rbac-test", other, role)
		assert.ErrorIs(t, err, ErrProjectAccessDenied, "another person as %s through a team link", role)
	}
	assert.Zero(t, written, "nothing reaches the store")
	_, err := uc.AddProjectMember(ctx, "rbac-test", other, auth.RoleMember)
	require.NoError(t, err, "member-level grants follow the effective role")

	direct = auth.RoleManager
	_, err = uc.AddProjectMember(ctx, "rbac-test", other, auth.RoleAdmin)
	assert.ErrorIs(t, err, ErrProjectAccessDenied, "the direct manager row is the ceiling, not the linked admin role")
	_, err = uc.AddProjectMember(ctx, "rbac-test", other, auth.RoleManager)
	require.NoError(t, err)
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

// The last-admin rule is the store's, enforced under its membership lock; the
// use case reports the store's refusal as ErrLastAdminForbidden.
func TestAddProjectMember_LastAdminInvariant(t *testing.T) {
	uc, pr := setupMembersRBACTest()
	const self = "00000000-0000-4000-8000-000000000007"
	pr.effectiveRoleFn = func(context.Context, string, string) (string, error) { return auth.RoleAdmin, nil }
	pr.getMemberFn = func(_ context.Context, projectID, userID string) (port.ProjectMember, error) {
		return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleAdmin}, nil
	}

	// The store refuses to demote the last admin.
	pr.upsertMemberFn = func(context.Context, string, string, string) (port.ProjectMember, error) {
		return port.ProjectMember{}, port.ErrLastAdmin
	}
	_, err := uc.AddProjectMember(projectRoleCtx(self, auth.RoleAdmin), "rbac-test", self, auth.RoleMember)
	assert.ErrorIs(t, err, ErrLastAdminForbidden)

	// With a second admin the store accepts the demotion.
	pr.upsertMemberFn = func(_ context.Context, projectID, userID, role string) (port.ProjectMember, error) {
		return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: role}, nil
	}
	m, err := uc.AddProjectMember(projectRoleCtx(self, auth.RoleAdmin), "rbac-test", self, auth.RoleMember)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleMember, m.Role)
}

func TestRemoveProjectMember_SelfExitAndLastAdmin(t *testing.T) {
	uc, pr := setupMembersRBACTest()
	const member = "00000000-0000-4000-8000-000000000001"
	const admin = "00000000-0000-4000-8000-000000000008"

	pr.getMemberFn = func(_ context.Context, projectID, userID string) (port.ProjectMember, error) {
		switch userID {
		case member:
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleMember}, nil
		case admin:
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleAdmin}, nil
		}
		return port.ProjectMember{}, port.ErrNotFound
	}
	pr.deleteMemberFn = func(context.Context, string, string) error { return nil }

	// 1. A member can leave.
	require.NoError(t, uc.RemoveProjectMember(projectRoleCtx(member, auth.RoleMember), "rbac-test", member))

	// 2. The sole admin cannot: the store refuses.
	pr.deleteMemberFn = func(context.Context, string, string) error { return port.ErrLastAdmin }
	err := uc.RemoveProjectMember(projectRoleCtx(admin, auth.RoleAdmin), "rbac-test", admin)
	assert.ErrorIs(t, err, ErrLastAdminForbidden)

	// 3. An admin can leave when the store sees another admin.
	pr.deleteMemberFn = func(context.Context, string, string) error { return nil }
	require.NoError(t, uc.RemoveProjectMember(projectRoleCtx(admin, auth.RoleAdmin), "rbac-test", admin))

	// 4. A caller below manager is refused before the store is asked, so a
	// missing member cannot be told from an existing one.
	pr.effectiveRoleFn = func(context.Context, string, string) (string, error) { return auth.RoleMember, nil }
	err = uc.RemoveProjectMember(projectRoleCtx(member, auth.RoleMember), "rbac-test", "00000000-0000-4000-8000-000000000099")
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

// The peer rule runs on the row the store reads under its membership lock, not
// on an earlier read. Here the earlier read still shows a member while the
// locked row is an admin who was promoted in between: the manager is refused,
// and nothing is written.
func TestMemberWrites_PeerRuleJudgesTheRowReadUnderTheLock(t *testing.T) {
	uc, pr := setupMembersRBACTest()
	const target = "00000000-0000-4000-8000-000000000002"
	pr.effectiveRoleFn = func(context.Context, string, string) (string, error) { return auth.RoleManager, nil }
	pr.getMemberFn = func(_ context.Context, projectID, userID string) (port.ProjectMember, error) {
		if userID == "mgr-1" {
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleManager}, nil
		}
		// What an unlocked read would have shown.
		return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleMember}, nil
	}
	written := 0
	locked := port.ProjectMember{UserID: target, Role: auth.RoleAdmin}
	pr.upsertMemberCheckedFn = func(_ context.Context, _, _, _ string, check port.MemberCheck) (port.ProjectMember, error) {
		if err := check(&locked); err != nil {
			return port.ProjectMember{}, err
		}
		written++
		return port.ProjectMember{}, nil
	}
	pr.deleteMemberCheckedFn = func(_ context.Context, _, _ string, check port.MemberCheck) error {
		if err := check(&locked); err != nil {
			return err
		}
		written++
		return nil
	}
	mgr := projectRoleCtx("mgr-1", auth.RoleManager)

	_, err := uc.AddProjectMember(mgr, "rbac-test", target, auth.RoleManager)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
	err = uc.RemoveProjectMember(mgr, "rbac-test", target)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
	assert.Zero(t, written)

	// Once the locked row is a member, the same writes go through.
	locked.Role = auth.RoleMember
	_, err = uc.AddProjectMember(mgr, "rbac-test", target, auth.RoleManager)
	require.NoError(t, err)
	require.NoError(t, uc.RemoveProjectMember(mgr, "rbac-test", target))
	assert.Equal(t, 2, written)
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
