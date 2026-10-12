package usecase

import (
	"context"
	"testing"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPermissionsForRole(t *testing.T) {
	member := ProjectPermissions{RequestWaiver: true}
	manager := ProjectPermissions{
		RequestWaiver: true, ManageWaivers: true, ApproveWaivers: true,
		ManageMembers: true, ManageCI: true, Triage: true,
	}
	for role, want := range map[string]ProjectPermissions{
		auth.RoleAdmin:   manager,
		auth.RoleManager: manager,
		"editor":         manager,
		auth.RoleMember:  member,
		"viewer":         member,
		"":               {},
		"guest":          {},
	} {
		assert.Equal(t, want, permissionsForRole(role), "role %q", role)
	}
}

// The permissions must agree with the predicates the write paths use, so the
// UI can never offer an action the server refuses for a documented reason.
func TestPermissionsMatchTheWritePathPredicates(t *testing.T) {
	for _, role := range []string{auth.RoleAdmin, auth.RoleManager, "editor", auth.RoleMember, "viewer", "guest", ""} {
		p := permissionsForRole(role)
		assert.Equal(t, waiverRequesterRole(role), p.RequestWaiver, role)
		assert.Equal(t, waiverApproverRole(role), p.ApproveWaivers, role)
		assert.Equal(t, auth.RoleRank(normalizeMemberRole(role)) >= auth.RoleRank(auth.RoleManager), p.ManageMembers,
			"%q: members are added by managers and above, as AddProjectMember allows", role)
	}
}

func permissionsUsecase(role string, member bool) *Usecases {
	project := makeProject(true)
	projects := &mockProjectRepo{
		getBySlugFn:     func(context.Context, string) (port.Project, error) { return project, nil },
		isMemberFn:      func(context.Context, string, string) (bool, error) { return member, nil },
		effectiveRoleFn: func(context.Context, string, string) (string, error) { return role, nil },
	}
	return New(Deps{Stores: &port.Stores{Projects: projects}})
}

func TestGetProjectReportsRoleAndPermissions(t *testing.T) {
	for _, tc := range []struct {
		name     string
		ctx      context.Context
		stored   string
		wantRole string
		wantMgr  bool
	}{
		{"member", sessionCtx("u1", auth.RoleMember), auth.RoleMember, auth.RoleMember, false},
		{"legacy viewer reads as member", sessionCtx("u1", auth.RoleMember), "viewer", auth.RoleMember, false},
		{"legacy editor reads as manager", sessionCtx("u1", auth.RoleMember), "editor", auth.RoleManager, true},
		{"manager", sessionCtx("u1", auth.RoleMember), auth.RoleManager, auth.RoleManager, true},
		{"global admin is admin everywhere", sessionCtx("u1", auth.RoleAdmin), "", auth.RoleAdmin, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := permissionsUsecase(tc.stored, true).GetProject(tc.ctx, "my-app")
			require.NoError(t, err)
			assert.Equal(t, tc.wantRole, resp.Role)
			require.NotNil(t, resp.Permissions)
			assert.True(t, resp.Permissions.RequestWaiver)
			assert.Equal(t, tc.wantMgr, resp.Permissions.ApproveWaivers)
		})
	}
}

func TestGetProjectOmitsRoleForAPIKeys(t *testing.T) {
	resp, err := permissionsUsecase("", false).GetProject(apiKeyCtx("key-1", makeProject(true).ID), "my-app")
	require.NoError(t, err)
	assert.Empty(t, resp.Role)
	assert.Nil(t, resp.Permissions)
}

func TestGetProjectStillDeniesNonMembers(t *testing.T) {
	_, err := permissionsUsecase(auth.RoleMember, false).GetProject(sessionCtx("u1", auth.RoleMember), "my-app")
	require.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestProjectAPIKeysNeedAManagerRole(t *testing.T) {
	keys := &mockAPIKeyRepo{
		createFn: func(_ context.Context, in port.CreateAPIKeyInput) (port.APIKey, error) {
			return port.APIKey{ID: "k1", Name: in.Name}, nil
		},
		listByProjectFn: func(context.Context, string) ([]port.APIKey, error) { return nil, nil },
		revokeFn:        func(context.Context, string, string) (port.APIKey, error) { return port.APIKey{}, nil },
	}
	const keyID = "00000000-0000-0000-0000-0000000000c1"
	const userID = "00000000-0000-0000-0000-0000000000a1"
	build := func(role string) *Usecases {
		uc := permissionsUsecase(role, true)
		uc.deps.Stores.APIKeys = keys
		return uc
	}
	ctx := sessionCtx(userID, auth.RoleMember)

	for _, role := range []string{auth.RoleMember, "viewer"} {
		uc := build(role)
		_, err := uc.CreateAPIKey(ctx, "my-app", "ci", userID, nil)
		require.ErrorIs(t, err, ErrProjectAccessDenied, "%s may not create keys", role)
		_, err = uc.ListAPIKeys(ctx, "my-app")
		require.ErrorIs(t, err, ErrProjectAccessDenied, "%s may not list keys", role)
		require.ErrorIs(t, uc.RevokeAPIKey(ctx, "my-app", keyID), ErrProjectAccessDenied, "%s may not revoke keys", role)
	}
	for _, role := range []string{auth.RoleManager, "editor", auth.RoleAdmin} {
		uc := build(role)
		_, err := uc.CreateAPIKey(ctx, "my-app", "ci", userID, nil)
		require.NoError(t, err, role)
		_, err = uc.ListAPIKeys(ctx, "my-app")
		require.NoError(t, err, role)
		require.NoError(t, uc.RevokeAPIKey(ctx, "my-app", keyID), role)
	}
}
