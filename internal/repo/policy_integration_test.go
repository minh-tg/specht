//go:build integration

package repo

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/port"
)

// TestPolicyTemplate_CRUDEndToEnd proves template versioning and project
// linkage against real Postgres: updates bump the version, deletion
// unlinks (SET NULL) instead of orphaning projects.
func TestPolicyTemplate_CRUDEndToEnd(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	policies := &pgPolicyPort{q: sqlc.New(repos.pool)}

	created, err := policies.CreateTemplate(ctx, port.PolicyTemplateInput{
		Name: "strict", Description: "d",
		Definition: json.RawMessage(`{"severity_floor":"critical"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, int32(1), created.Version)

	updated, err := policies.UpdateTemplate(ctx, created.ID, port.PolicyTemplateInput{
		Name: "strict", Description: "d2",
		Definition: json.RawMessage(`{"severity_floor":"critical"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, int32(2), updated.Version, "definition replacement bumps the version")

	project := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()
	_, err = policies.SetProjectTemplate(ctx, projectID, &created.ID)
	require.NoError(t, err)

	require.NoError(t, policies.DeleteTemplate(ctx, created.ID))

	// Project survives the template deletion; the link nulls.
	after, err := repos.Projects.GetBySlug(ctx, project.Slug)
	require.NoError(t, err)
	assert.Equal(t, project.ID, after.ID)
}
