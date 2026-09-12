package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/port"
)

func projectUpdateRepos() *mockProjectRepo {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		desc := "old description"
		return port.Project{
			ID:          findingFixtureProjectID,
			Slug:        "my-app",
			Name:        "My App",
			Description: &desc,
		}, nil
	}
	return pr
}

func strptr(s string) *string { return &s }

func TestUpdateProject_GlobalAdminAllowed(t *testing.T) {
	pr := projectUpdateRepos()
	var gotName string
	var gotDesc *string
	pr.updateFn = func(ctx context.Context, slug, name string, description *string) (port.Project, error) {
		gotName = name
		gotDesc = description
		return port.Project{ID: findingFixtureProjectID, Slug: slug, Name: name, Description: description}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	resp, err := uc.UpdateProject(sessionCtx("admin-1", auth.RoleAdmin), "my-app", strptr("Renamed"), strptr("new desc"))
	require.NoError(t, err)
	assert.Equal(t, "Renamed", gotName)
	require.NotNil(t, gotDesc)
	assert.Equal(t, "new desc", *gotDesc)
	assert.Equal(t, "Renamed", resp.Name)
}

func TestUpdateProject_ProjectAdminAllowed(t *testing.T) {
	pr := projectUpdateRepos()
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return []port.ProjectMember{{ProjectID: projectID, UserID: "admin-1", Role: auth.RoleAdmin}}, nil
	}
	pr.updateFn = func(ctx context.Context, slug, name string, description *string) (port.Project, error) {
		return port.Project{ID: findingFixtureProjectID, Slug: slug, Name: name, Description: description}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	resp, err := uc.UpdateProject(sessionCtx("admin-1", auth.RoleViewer), "my-app", strptr("Renamed"), nil)
	require.NoError(t, err)
	assert.Equal(t, "Renamed", resp.Name)
}

func TestUpdateProject_NonAdminDenied(t *testing.T) {
	pr := projectUpdateRepos()
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return []port.ProjectMember{{ProjectID: projectID, UserID: "u1", Role: auth.RoleViewer}}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	_, err := uc.UpdateProject(sessionCtx("u1", auth.RoleViewer), "my-app", strptr("Renamed"), nil)
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestUpdateProject_NotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return port.Project{}, port.ErrNotFound
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	_, err := uc.UpdateProject(sessionCtx("admin-1", auth.RoleAdmin), "missing", strptr("Renamed"), nil)
	assert.ErrorContains(t, err, "project not found")
}

func TestDeleteProject_GlobalAdminAllowed(t *testing.T) {
	pr := projectUpdateRepos()
	var gotSlug string
	pr.deleteFn = func(ctx context.Context, slug string) (port.Project, error) {
		gotSlug = slug
		return port.Project{ID: findingFixtureProjectID, Slug: slug, Name: "My App"}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	resp, err := uc.DeleteProject(sessionCtx("admin-1", auth.RoleAdmin), "my-app")
	require.NoError(t, err)
	assert.Equal(t, "my-app", gotSlug)
	assert.Equal(t, "my-app", resp.Slug)
}

func TestDeleteProject_NonAdminDenied(t *testing.T) {
	pr := projectUpdateRepos()
	pr.listMembersFn = func(ctx context.Context, projectID string) ([]port.ProjectMember, error) {
		return []port.ProjectMember{{ProjectID: projectID, UserID: "u1", Role: auth.RoleViewer}}, nil
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	_, err := uc.DeleteProject(sessionCtx("u1", auth.RoleViewer), "my-app")
	assert.ErrorIs(t, err, ErrProjectAccessDenied)
}

func TestDeleteProject_NotFound(t *testing.T) {
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
		return port.Project{}, port.ErrNotFound
	}
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	_, err := uc.DeleteProject(sessionCtx("admin-1", auth.RoleAdmin), "missing")
	assert.ErrorContains(t, err, "project not found")
}
