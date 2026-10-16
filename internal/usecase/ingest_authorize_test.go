package usecase

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
)

// AuthorizeIngest answers whether the caller may ingest into a project before
// any of the report is read.
func TestAuthorizeIngest(t *testing.T) {
	role := auth.RoleViewer
	pr := &mockProjectRepo{}
	pr.getBySlugFn = func(_ context.Context, slug string) (port.Project, error) {
		if slug != "my-app" {
			return port.Project{}, port.ErrNotFound
		}
		return makeProject(true), nil
	}
	pr.effectiveRoleFn = func(context.Context, string, string) (string, error) { return role, nil }
	uc := New(Deps{Stores: &port.Stores{Projects: pr}})
	ingestKey := func(projectID string, scopes ...string) context.Context {
		return auth.ContextWithIdentity(context.Background(), &auth.Identity{UserID: "creator", ProjectID: projectID, IsAPIKey: true, Scopes: scopes})
	}

	assert.ErrorIs(t, uc.AuthorizeIngest(sessionCtx("u1", auth.RoleViewer), "my-app"), ErrProjectAccessDenied, "a viewer cannot ingest")
	role = auth.RoleMember
	assert.ErrorIs(t, uc.AuthorizeIngest(sessionCtx("u1", auth.RoleViewer), "my-app"), ErrProjectAccessDenied, "a member cannot ingest")
	role = auth.RoleEditor
	assert.NoError(t, uc.AuthorizeIngest(sessionCtx("u1", auth.RoleViewer), "my-app"), "an editor can")

	assert.NoError(t, uc.AuthorizeIngest(ingestKey(findingFixtureProjectID, auth.ScopeIngest), "my-app"))
	assert.ErrorIs(t, uc.AuthorizeIngest(ingestKey(findingFixtureProjectID, auth.ScopeRead), "my-app"), ErrProjectAccessDenied, "a read key cannot")
	assert.ErrorIs(t, uc.AuthorizeIngest(ingestKey("11111111-1111-1111-1111-111111111111", auth.ScopeIngest), "my-app"), ErrProjectAccessDenied, "another project's key cannot")

	err := uc.AuthorizeIngest(sessionCtx("u1", auth.RoleEditor), "missing")
	require.ErrorIs(t, err, ErrProjectAccessDenied, "a missing project answers like a project the caller cannot reach")
	assert.ErrorIs(t, uc.AuthorizeIngest(context.Background(), "my-app"), ErrProjectAccessDenied, "no identity")
}
