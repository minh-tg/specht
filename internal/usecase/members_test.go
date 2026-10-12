package usecase

import (
	"context"
	"testing"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func memberTestProject() port.Project {
	return port.Project{ID: findingFixtureProjectID, Slug: "my-app", Name: "My App"}
}

func TestListProjectMembers_GlobalAdminAllowed(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return memberTestProject(), nil
	}
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return []port.ProjectMember{{ProjectID: projectID, UserID: "u1", Role: auth.RoleViewer}}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	members, err := uc.ListProjectMembers(sessionCtx("00000000-0000-4000-8000-000000000007", auth.RoleAdmin), "my-app")
	require.NoError(t, err)
	require.Len(t, members, 1)
	assert.Equal(t, "u1", members[0].UserID)
}

func TestListProjectMembers_NamesGoToPeopleAndNotToKeys(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return memberTestProject(), nil
	}
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return []port.ProjectMember{{
			ProjectID: projectID, UserID: "u1", Role: auth.RoleViewer,
			Email: "ada@acme.example", DisplayName: "Ada Okafor",
		}}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})

	person, err := uc.ListProjectMembers(sessionCtx("00000000-0000-4000-8000-000000000007", auth.RoleAdmin), "my-app")
	require.NoError(t, err)
	require.Len(t, person, 1)
	assert.Equal(t, "ada@acme.example", person[0].Email)
	assert.Equal(t, "Ada Okafor", person[0].DisplayName)

	key, err := uc.ListProjectMembers(apiKeyCtx("key-1", memberTestProject().ID), "my-app")
	require.NoError(t, err)
	require.Len(t, key, 1)
	assert.Equal(t, "u1", key[0].UserID, "a key still sees who holds which role")
	assert.Empty(t, key[0].Email, "but not their addresses")
	assert.Empty(t, key[0].DisplayName)
}

func TestListProjectMembers_NonMemberDenied(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return memberTestProject(), nil
	}
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return []port.ProjectMember{{ProjectID: projectID, UserID: "other", Role: auth.RoleViewer}}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	_, err := uc.ListProjectMembers(sessionCtx("u1", auth.RoleViewer), "my-app")
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestAddProjectMember_ProjectAdminAllowed(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return memberTestProject(), nil
	}
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return []port.ProjectMember{{ProjectID: projectID, UserID: "00000000-0000-4000-8000-000000000007", Role: auth.RoleAdmin}}, nil
	}
	pr.upsertMemberFn = func(ctx context.Context, projectID, userID, role string) (port.ProjectMember, error) {
		return port.ProjectMember{ProjectID: projectID, UserID: userID, Role: role}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	m, err := uc.AddProjectMember(sessionCtx("00000000-0000-4000-8000-000000000007", auth.RoleViewer), "my-app", "00000000-0000-4000-8000-000000000012", auth.RoleManager)
	require.NoError(t, err)
	assert.Equal(t, "00000000-0000-4000-8000-000000000012", m.UserID)
	assert.Equal(t, auth.RoleManager, m.Role)
}

func TestAddProjectMember_InvalidRoleRejected(t *testing.T) {
	uc := New(Deps{Stores: &port.Stores{Projects: &mockProjectRepo{}}})
	_, err := uc.AddProjectMember(sessionCtx("00000000-0000-4000-8000-000000000007", auth.RoleAdmin), "my-app", "00000000-0000-4000-8000-000000000012", "superuser")
	assert.ErrorContains(t, err, "invalid member role")
}

func TestAddProjectMember_NonAdminDenied(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return memberTestProject(), nil
	}
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return []port.ProjectMember{{ProjectID: projectID, UserID: "u1", Role: auth.RoleViewer}}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	_, err := uc.AddProjectMember(sessionCtx("u1", auth.RoleViewer), "my-app", "00000000-0000-4000-8000-000000000012", auth.RoleViewer)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}
