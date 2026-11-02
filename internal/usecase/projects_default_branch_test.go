package usecase

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

func TestUpdateProject_DefaultBranch(t *testing.T) {
	run := func(t *testing.T, current, requested *string) (*string, error) {
		t.Helper()
		pr := projectUpdateRepos()
		get := pr.getBySlugFn
		pr.getBySlugFn = func(ctx context.Context, slug string) (port.Project, error) {
			p, err := get(ctx, slug)
			p.DefaultBranch = current
			return p, err
		}
		var written *string
		pr.updateFn = func(ctx context.Context, slug, name string, description, defaultBranch *string) (port.Project, error) {
			written = defaultBranch
			assert.Equal(t, "My App", name, "the name is kept")
			return port.Project{ID: findingFixtureProjectID, Slug: slug, Name: name, Description: description, DefaultBranch: defaultBranch}, nil
		}
		uc := New(Deps{Stores: &port.Stores{Projects: pr}})
		resp, err := uc.UpdateProject(sessionCtx("admin-1", auth.RoleAdmin), "my-app", nil, nil, requested)
		if err != nil {
			return nil, err
		}
		assert.Equal(t, written, resp.DefaultBranch)
		return written, nil
	}

	got, err := run(t, nil, strptr("  main "))
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "main", *got, "the value is trimmed")

	got, err = run(t, strptr("main"), nil)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.Equal(t, "main", *got, "an absent field keeps the stored branch")

	got, err = run(t, strptr("main"), strptr("  "))
	require.NoError(t, err)
	assert.Nil(t, got, "a blank value clears it")

	for _, bad := range []string{"main\x00", "ma\nin", strings.Repeat("b", 256)} {
		_, err = run(t, nil, &bad)
		assert.ErrorIs(t, err, ErrInvalidDefaultBranch, "%q", bad)
	}
	long := strings.Repeat("b", 255)
	_, err = run(t, nil, &long)
	assert.NoError(t, err, "255 bytes is the limit")
}

// Only a global admin or a project admin may set the default branch: a
// manager, a member and an API key may not.
func TestUpdateProject_DefaultBranchNeedsAProjectAdmin(t *testing.T) {
	for _, role := range []string{auth.RoleManager, auth.RoleMember} {
		t.Run(role, func(t *testing.T) {
			pr := projectUpdateRepos()
			pr.effectiveRoleFn = func(ctx context.Context, projectID, userID string) (string, error) {
				return role, nil
			}
			pr.updateFn = func(ctx context.Context, slug, name string, description, defaultBranch *string) (port.Project, error) {
				t.Fatal("a non-admin must not write")
				return port.Project{}, nil
			}
			uc := New(Deps{Stores: &port.Stores{Projects: pr}})
			_, err := uc.UpdateProject(sessionCtx("u1", auth.RoleViewer), "my-app", nil, nil, strptr("main"))
			assert.ErrorIs(t, err, ErrProjectAccessDenied)
		})
	}
	t.Run("api key", func(t *testing.T) {
		pr := projectUpdateRepos()
		uc := New(Deps{Stores: &port.Stores{Projects: pr}})
		_, err := uc.UpdateProject(apiKeyCtx("key-1", findingFixtureProjectID), "my-app", nil, nil, strptr("main"))
		assert.ErrorIs(t, err, ErrProjectAccessDenied)
	})
}
