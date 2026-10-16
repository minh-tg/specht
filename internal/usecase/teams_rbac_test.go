package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

func TestLinkProjectTeam_DelegationCeilingAndPeerProtection(t *testing.T) {
	uc, pr, tr, _ := teamHarness()
	p := rbacTestProject()
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return p, nil
	}
	tr.getByIDFn = func(ctx context.Context, id string) (port.Team, error) {
		return port.Team{ID: id, Name: "team-" + id}, nil
	}

	// 1. Manager caller
	pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
		if userID == "mgr-1" {
			return auth.RoleManager, nil
		}
		if userID == "admin-1" {
			return auth.RoleAdmin, nil
		}
		return "", port.ErrNotFound
	}

	pr.getMemberFn = func(ctx context.Context, projectID, userID string) (port.ProjectMember, error) {
		switch userID {
		case "mgr-1":
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleManager}, nil
		case "admin-1":
			return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: auth.RoleAdmin}, nil
		}
		return port.ProjectMember{}, port.ErrNotFound
	}

	tr.linkFn = func(ctx context.Context, projectID, teamID, role string) (port.ProjectTeam, error) {
		return port.ProjectTeam{ProjectID: projectID, TeamID: teamID, Role: role}, nil
	}
	tr.listLinksFn = func(ctx context.Context, projectID string) ([]port.ProjectTeam, error) {
		return nil, nil
	}

	// Manager can link as Member
	link, err := uc.LinkProjectTeam(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", "11111111-1111-1111-1111-111111111111", auth.RoleMember)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleMember, link.Role)

	// Manager can link as Manager
	link, err = uc.LinkProjectTeam(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", "11111111-1111-1111-1111-111111111111", auth.RoleManager)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleManager, link.Role)

	// Manager CANNOT link as Admin (delegation ceiling)
	_, err = uc.LinkProjectTeam(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", "11111111-1111-1111-1111-111111111111", auth.RoleAdmin)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	// Admin CAN link as Admin
	link, err = uc.LinkProjectTeam(projectRoleCtx("admin-1", auth.RoleAdmin), "rbac-test", "11111111-1111-1111-1111-111111111111", auth.RoleAdmin)
	require.NoError(t, err)
	assert.Equal(t, auth.RoleAdmin, link.Role)

	adminTeamID := "22222222-2222-2222-2222-222222222222"
	memberTeamID := "33333333-3333-3333-3333-333333333333"

	// 2. Unlink protection:
	tr.listLinksFn = func(ctx context.Context, projectID string) ([]port.ProjectTeam, error) {
		return []port.ProjectTeam{
			{ProjectID: projectID, TeamID: adminTeamID, Role: auth.RoleAdmin},
			{ProjectID: projectID, TeamID: memberTeamID, Role: auth.RoleMember},
		}, nil
	}
	tr.unlinkFn = func(ctx context.Context, projectID, teamID string) error {
		return nil
	}

	// Manager can unlink Member team
	err = uc.UnlinkProjectTeam(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", memberTeamID)
	require.NoError(t, err)

	// Manager CANNOT unlink Admin team
	err = uc.UnlinkProjectTeam(projectRoleCtx("mgr-1", auth.RoleManager), "rbac-test", adminTeamID)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)

	// Admin CAN unlink Admin team
	err = uc.UnlinkProjectTeam(projectRoleCtx("admin-1", auth.RoleAdmin), "rbac-test", adminTeamID)
	require.NoError(t, err)
}

func TestLinkProjectTeam_ExistingLinkPeerProtection(t *testing.T) {
	const (
		adminTeamID   = "22222222-2222-2222-2222-222222222222"
		managerTeamID = "33333333-3333-3333-3333-333333333333"
		memberTeamID  = "44444444-4444-4444-4444-444444444444"
		freshTeamID   = "55555555-5555-5555-5555-555555555555"
	)
	tests := []struct {
		name       string
		caller     string
		teamID     string
		role       string
		wantDenied bool
	}{
		{"manager cannot demote an admin team", auth.RoleManager, adminTeamID, auth.RoleMember, true},
		{"manager cannot demote a peer manager team", auth.RoleManager, managerTeamID, auth.RoleMember, true},
		{"manager cannot rewrite a peer manager team", auth.RoleManager, managerTeamID, auth.RoleManager, true},
		{"manager can promote a member team", auth.RoleManager, memberTeamID, auth.RoleManager, false},
		{"manager can relink a member team", auth.RoleManager, memberTeamID, auth.RoleMember, false},
		{"manager can link a new team", auth.RoleManager, freshTeamID, auth.RoleMember, false},
		{"admin can demote an admin team", auth.RoleAdmin, adminTeamID, auth.RoleMember, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			uc, pr, tr, _ := teamHarness()
			pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
				return rbacTestProject(), nil
			}
			pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
				return tc.caller, nil
			}
			pr.getMemberFn = func(ctx context.Context, projectID, userID string) (port.ProjectMember, error) {
				return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: tc.caller}, nil
			}
			tr.getByIDFn = func(ctx context.Context, id string) (port.Team, error) {
				return port.Team{ID: id, Name: "team-" + id}, nil
			}
			tr.listLinksFn = func(ctx context.Context, projectID string) ([]port.ProjectTeam, error) {
				return []port.ProjectTeam{
					{ProjectID: projectID, TeamID: adminTeamID, Role: auth.RoleAdmin},
					{ProjectID: projectID, TeamID: managerTeamID, Role: auth.RoleManager},
					{ProjectID: projectID, TeamID: memberTeamID, Role: auth.RoleMember},
				}, nil
			}
			written := false
			tr.linkFn = func(ctx context.Context, projectID, teamID, role string) (port.ProjectTeam, error) {
				written = true
				return port.ProjectTeam{ProjectID: projectID, TeamID: teamID, Role: role}, nil
			}

			_, err := uc.LinkProjectTeam(projectRoleCtx("caller-1", tc.caller), "rbac-test", tc.teamID, tc.role)
			if tc.wantDenied {
				assert.ErrorIs(t, err, ErrProjectAccessDenied)
				assert.False(t, written, "a denied relink must not reach the store")
				return
			}
			require.NoError(t, err)
			assert.True(t, written)
		})
	}
}

// A team link cannot vouch for a link written on its strength: a caller with no
// direct row may link a team at member level only.
func TestLinkProjectTeam_TeamOnlyCallerIsCappedAtMember(t *testing.T) {
	uc, pr, tr, _ := teamHarness()
	pr.getBySlugFn = func(context.Context, string) (port.Project, error) { return rbacTestProject(), nil }
	pr.effectiveRoleFn = func(context.Context, string, string) (string, error) { return auth.RoleAdmin, nil }
	tr.getByIDFn = func(_ context.Context, id string) (port.Team, error) { return port.Team{ID: id, Name: "t"}, nil }
	tr.listLinksFn = func(context.Context, string) ([]port.ProjectTeam, error) { return nil, nil }
	written := 0
	tr.linkFn = func(_ context.Context, projectID, teamID, role string) (port.ProjectTeam, error) {
		written++
		return port.ProjectTeam{ProjectID: projectID, TeamID: teamID, Role: role}, nil
	}
	ctx := projectRoleCtx("caller-1", auth.RoleViewer)
	const team = "11111111-1111-1111-1111-111111111111"

	for _, role := range []string{auth.RoleAdmin, auth.RoleManager} {
		_, err := uc.LinkProjectTeam(ctx, "rbac-test", team, role)
		assert.ErrorIs(t, err, ErrProjectAccessDenied, role)
	}
	assert.Zero(t, written)
	_, err := uc.LinkProjectTeam(ctx, "rbac-test", team, auth.RoleMember)
	require.NoError(t, err)
}
