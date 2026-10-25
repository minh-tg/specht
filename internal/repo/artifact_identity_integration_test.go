//go:build integration

package repo

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func newArtifactProject(t *testing.T, ctx context.Context, stores *port.Stores) string {
	t.Helper()
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "artifact-identity", Name: "Artifact identity",
		DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	return project.ID
}

func TestArtifactUpsert_WithoutDigestReusesTheRow(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	project := newArtifactProject(t, ctx, stores)

	upsert := func(version string) port.Artifact {
		t.Helper()
		a, err := stores.Artifacts.Upsert(ctx, port.ArtifactInput{
			ProjectID: project, ArtifactType: "container_image",
			Name: "myapp", Version: strPtr(version), Metadata: json.RawMessage("{}"),
		})
		require.NoError(t, err)
		return a
	}
	first := upsert("1")
	second := upsert("2")
	assert.Equal(t, first.ID, second.ID, "a name without a digest is one artifact, not one per scan")

	all, err := stores.Artifacts.List(ctx, project)
	require.NoError(t, err)
	require.Len(t, all, 1)
	require.NotNil(t, all[0].Version)
	assert.Equal(t, "2", *all[0].Version, "the newest scan's fields win")
}

func TestArtifactUpsert_SameDigestUnderANewNameIsTheSameArtifact(t *testing.T) {
	pool, cleanup := setupIngestPool(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(pool)
	project := newArtifactProject(t, ctx, stores)

	upsert := func(name string) port.Artifact {
		t.Helper()
		a, err := stores.Artifacts.Upsert(ctx, port.ArtifactInput{
			ProjectID: project, ArtifactType: "container_image",
			Name: name, Digest: strPtr("sha256:aaa"), Metadata: json.RawMessage("{}"),
		})
		require.NoError(t, err, "a second tag for one digest must not hit the digest index")
		return a
	}
	tagged := upsert("app:1.2")
	latest := upsert("app:latest")
	assert.Equal(t, tagged.ID, latest.ID, "the digest identifies the artifact, the tag does not")
	assert.Equal(t, "app:1.2", latest.Name, "the first name stays")
}
