//go:build integration

package repo

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/require"
)

func TestPortAdapterLifecycle(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()

	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	createProject := func(slug string) port.Project {
		project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
			Slug:                slug,
			Name:                slug,
			DeploymentThreshold: "high",
			Settings:            json.RawMessage(`{}`),
		})
		require.NoError(t, err)
		return project
	}
	project := createProject("port-lifecycle")
	otherProject := createProject("port-lifecycle-other")

	// Exercise the sqlc-backed repositories directly as well as their port
	// adapters; the repository wrappers are part of the production contract.
	projectUUID := mustParseID(project.ID)
	lowLevelEnvironment, err := repos.Environments.Upsert(ctx, sqlc.UpsertEnvironmentParams{
		ProjectID:       projectUUID,
		Name:            "staging",
		Tier:            "staging",
		InternetFacing:  false,
		DataSensitivity: "public",
	})
	require.NoError(t, err)
	lowLevelEnvironments, err := repos.Environments.List(ctx, projectUUID)
	require.NoError(t, err)
	require.Len(t, lowLevelEnvironments, 1)
	gotLowLevelEnvironment, err := repos.Environments.GetByID(ctx, lowLevelEnvironment.ID, projectUUID)
	require.NoError(t, err)
	require.Equal(t, lowLevelEnvironment.ID, gotLowLevelEnvironment.ID)
	deletedLowLevelEnvironment, err := repos.Environments.Delete(ctx, lowLevelEnvironment.ID, projectUUID)
	require.NoError(t, err)
	require.Equal(t, lowLevelEnvironment.ID, deletedLowLevelEnvironment.ID)

	lowLevelTarget, err := repos.Targets.Upsert(ctx, sqlc.UpsertTargetParams{
		ProjectID: projectUUID,
		Name:      "low-level-target",
		Kind:      "repo",
		Locator:   pgtype.Text{String: "https://example.com/repo", Valid: true},
		Column5:   "github://example/repo",
	})
	require.NoError(t, err)
	lowLevelTargets, err := repos.Targets.List(ctx, projectUUID)
	require.NoError(t, err)
	require.Len(t, lowLevelTargets, 1)
	gotLowLevelTarget, err := repos.Targets.GetByID(ctx, lowLevelTarget.ID, projectUUID)
	require.NoError(t, err)
	require.Equal(t, lowLevelTarget.ID, gotLowLevelTarget.ID)

	lowLevelArtifact, err := repos.Artifacts.Upsert(ctx, sqlc.UpsertArtifactParams{
		ProjectID:    projectUUID,
		TargetID:     lowLevelTarget.ID,
		ArtifactType: "container_image",
		Name:         "low-level-artifact",
		Version:      pgtype.Text{String: "1.0.0", Valid: true},
		Digest:       pgtype.Text{String: "sha256:low-level", Valid: true},
		Locator:      pgtype.Text{String: "registry.example/low-level:1.0.0", Valid: true},
		Metadata:     []byte(`{"source":"integration"}`),
	})
	require.NoError(t, err)
	lowLevelArtifacts, err := repos.Artifacts.List(ctx, projectUUID)
	require.NoError(t, err)
	require.Len(t, lowLevelArtifacts, 1)
	artifactsByLowLevelTarget, err := repos.Artifacts.ListByTarget(ctx, lowLevelTarget.ID)
	require.NoError(t, err)
	require.Len(t, artifactsByLowLevelTarget, 1)
	gotLowLevelArtifact, err := repos.Artifacts.GetByID(ctx, lowLevelArtifact.ID, projectUUID)
	require.NoError(t, err)
	require.Equal(t, lowLevelArtifact.ID, gotLowLevelArtifact.ID)
	deletedLowLevelArtifact, err := repos.Artifacts.Delete(ctx, lowLevelArtifact.ID, projectUUID)
	require.NoError(t, err)
	require.Equal(t, lowLevelArtifact.ID, deletedLowLevelArtifact.ID)
	deletedLowLevelTarget, err := repos.Targets.Delete(ctx, lowLevelTarget.ID, projectUUID)
	require.NoError(t, err)
	require.Equal(t, lowLevelTarget.ID, deletedLowLevelTarget.ID)

	environment, err := stores.Environments.Upsert(ctx, project.ID, "production", "production", true, "confidential")
	require.NoError(t, err)
	environments, err := stores.Environments.List(ctx, project.ID)
	require.NoError(t, err)
	require.Len(t, environments, 1)
	gotEnvironment, err := stores.Environments.GetByID(ctx, environment.ID, project.ID)
	require.NoError(t, err)
	require.Equal(t, environment.ID, gotEnvironment.ID)
	_, err = stores.Environments.GetByID(ctx, environment.ID, otherProject.ID)
	require.ErrorIs(t, err, port.ErrNotFound)

	target, err := stores.Targets.Upsert(ctx, project.ID, "specht", "repo", "https://github.com/example/specht", "github://example/specht")
	require.NoError(t, err)
	target, err = stores.Targets.Upsert(ctx, project.ID, "specht", "repo", "https://github.com/example/specht", "")
	require.NoError(t, err)
	require.NotNil(t, target.Owner)
	require.Equal(t, "github://example/specht", *target.Owner)
	targets, err := stores.Targets.List(ctx, project.ID)
	require.NoError(t, err)
	require.Len(t, targets, 1)
	gotTarget, err := stores.Targets.GetByID(ctx, target.ID, project.ID)
	require.NoError(t, err)
	require.Equal(t, target.ID, gotTarget.ID)
	_, err = stores.Targets.GetByID(ctx, target.ID, otherProject.ID)
	require.ErrorIs(t, err, port.ErrNotFound)

	version := "1.0.0"
	digest := "sha256:production"
	locator := "registry.example/specht:1.0.0"
	artifact, err := stores.Artifacts.Upsert(ctx, port.ArtifactInput{
		ProjectID:    project.ID,
		TargetID:     target.ID,
		ArtifactType: "container_image",
		Name:         "specht",
		Version:      &version,
		Digest:       &digest,
		Locator:      &locator,
		Metadata:     json.RawMessage(`{"channel":"stable"}`),
	})
	require.NoError(t, err)
	projectArtifacts, err := stores.Artifacts.List(ctx, project.ID)
	require.NoError(t, err)
	require.Len(t, projectArtifacts, 1)
	targetArtifacts, err := stores.Artifacts.ListByTarget(ctx, target.ID)
	require.NoError(t, err)
	require.Len(t, targetArtifacts, 1)
	gotArtifact, err := stores.Artifacts.GetByID(ctx, artifact.ID, project.ID)
	require.NoError(t, err)
	require.Equal(t, artifact.ID, gotArtifact.ID)
	_, err = stores.Artifacts.GetByID(ctx, artifact.ID, otherProject.ID)
	require.ErrorIs(t, err, port.ErrNotFound)

	now := time.Now().UTC()
	finding, err := stores.Findings.Upsert(ctx, port.UpsertFindingInput{
		ProjectID:    project.ID,
		FindingKind:  "sca",
		Fingerprint:  "port-lifecycle-finding",
		Title:        "Outdated dependency",
		Severity:     "high",
		SeverityRank: 3,
		Score:        8.2,
		FirstSeen:    now,
		LastSeen:     now,
	})
	require.NoError(t, err)
	waiver, err := stores.Waivers.CreateWithDetails(ctx, port.CreateWaiverInput{
		ProjectID:   project.ID,
		Name:        "release exception",
		Description: "temporary release scope",
		Enabled:     true,
		Conditions: []port.WaiverCondition{{
			Field:    "finding_kind",
			Operator: "eq",
			Value:    "sca",
		}},
		Contexts: []port.WaiverContext{{
			EnvironmentID: environment.ID,
			TargetID:      target.ID,
			ArtifactID:    artifact.ID,
		}},
		Targets: []port.WaiverFindingTarget{{FindingID: finding.ID}},
		Event: port.WaiverEventInput{
			EventType: "created",
			ActorID:   stringPointer("operator-1"),
			Metadata:  json.RawMessage(`{"ticket":"SEC-42"}`),
		},
	})
	require.NoError(t, err)
	waivers, err := stores.Waivers.List(ctx, project.ID)
	require.NoError(t, err)
	require.Len(t, waivers, 1)
	gotWaiver, err := stores.Waivers.GetByID(ctx, waiver.ID, project.ID)
	require.NoError(t, err)
	require.Equal(t, waiver.ID, gotWaiver.ID)
	_, err = stores.Waivers.GetByID(ctx, waiver.ID, otherProject.ID)
	require.ErrorIs(t, err, port.ErrNotFound)
	activeWaivers, err := stores.Waivers.ListActive(ctx, project.ID)
	require.NoError(t, err)
	require.Len(t, activeWaivers, 1)

	conditions, err := stores.Waivers.ListConditions(ctx, waiver.ID)
	require.NoError(t, err)
	require.Len(t, conditions, 1)
	require.Equal(t, "finding_kind", conditions[0].Field)
	conditionsByWaiver, err := stores.Waivers.ListConditionsByWaiverIDs(ctx, []string{waiver.ID})
	require.NoError(t, err)
	require.Len(t, conditionsByWaiver, 1)
	contexts, err := stores.Waivers.ListContexts(ctx, waiver.ID)
	require.NoError(t, err)
	require.Len(t, contexts, 1)
	require.Equal(t, environment.ID, contexts[0].EnvironmentID)
	require.Equal(t, target.ID, contexts[0].TargetID)
	require.Equal(t, artifact.ID, contexts[0].ArtifactID)
	contextsByWaiver, err := stores.Waivers.ListContextsByWaiverIDs(ctx, []string{waiver.ID})
	require.NoError(t, err)
	require.Len(t, contextsByWaiver, 1)
	findingTargets, err := stores.Waivers.ListFindingTargets(ctx, waiver.ID)
	require.NoError(t, err)
	require.Len(t, findingTargets, 1)
	require.Equal(t, finding.ID, findingTargets[0].FindingID)
	findingTargetsByWaiver, err := stores.Waivers.ListFindingTargetsByWaiverIDs(ctx, []string{waiver.ID})
	require.NoError(t, err)
	require.Len(t, findingTargetsByWaiver, 1)
	events, err := stores.Waivers.ListEvents(ctx, waiver.ID)
	require.NoError(t, err)
	require.Len(t, events, 1)
	require.Equal(t, "created", events[0].EventType)
	require.Equal(t, "operator-1", events[0].ActorID)
	require.JSONEq(t, `{"ticket":"SEC-42"}`, string(events[0].Metadata))

	updatedWaiver, err := stores.Waivers.UpdateWithDetails(ctx, port.Waiver{
		ID:          waiver.ID,
		ProjectID:   project.ID,
		Name:        "updated release exception",
		Description: "updated scope description",
	}, nil, nil, nil, nil, port.WaiverEventInput{
		EventType: "updated",
		Metadata:  json.RawMessage(`{"change":"description"}`),
	})
	require.NoError(t, err)
	require.Equal(t, "updated release exception", updatedWaiver.Name)
	conditions, err = stores.Waivers.ListConditions(ctx, waiver.ID)
	require.NoError(t, err)
	require.Len(t, conditions, 1)
	contexts, err = stores.Waivers.ListContexts(ctx, waiver.ID)
	require.NoError(t, err)
	require.Len(t, contexts, 1)
	findingTargets, err = stores.Waivers.ListFindingTargets(ctx, waiver.ID)
	require.NoError(t, err)
	require.Len(t, findingTargets, 1)

	emptyConditions := []port.WaiverCondition{}
	emptyContexts := []port.WaiverContext{}
	emptyTargets := []port.WaiverFindingTarget{}
	_, err = stores.Waivers.UpdateWithDetails(ctx, port.Waiver{
		ID:        waiver.ID,
		ProjectID: project.ID,
	}, nil, &emptyConditions, &emptyContexts, &emptyTargets, port.WaiverEventInput{
		EventType: "details_cleared",
		Metadata:  json.RawMessage(`{}`),
	})
	require.NoError(t, err)
	conditions, err = stores.Waivers.ListConditions(ctx, waiver.ID)
	require.NoError(t, err)
	require.Empty(t, conditions)
	contexts, err = stores.Waivers.ListContexts(ctx, waiver.ID)
	require.NoError(t, err)
	require.Empty(t, contexts)
	findingTargets, err = stores.Waivers.ListFindingTargets(ctx, waiver.ID)
	require.NoError(t, err)
	require.Empty(t, findingTargets)

	disabledWaiver, err := stores.Waivers.ToggleWithEvent(ctx, waiver.ID, project.ID, "operator-1")
	require.NoError(t, err)
	require.False(t, disabledWaiver.Enabled)
	activeWaivers, err = stores.Waivers.ListActive(ctx, project.ID)
	require.NoError(t, err)
	require.Empty(t, activeWaivers)
	enabledWaiver, err := stores.Waivers.ToggleWithEvent(ctx, waiver.ID, project.ID, "operator-1")
	require.NoError(t, err)
	require.True(t, enabledWaiver.Enabled)
	allWaiverEvents, err := stores.Waivers.ListEvents(ctx, waiver.ID)
	require.NoError(t, err)
	eventTypes := make([]string, 0, len(allWaiverEvents))
	for _, event := range allWaiverEvents {
		eventTypes = append(eventTypes, event.EventType)
	}
	require.ElementsMatch(t, []string{"created", "updated", "details_cleared", "disabled", "enabled"}, eventTypes)

	_, err = stores.Waivers.GetByID(ctx, "not-a-uuid", project.ID)
	require.Error(t, err)
	_, err = stores.Waivers.ListConditionsByWaiverIDs(ctx, []string{"not-a-uuid"})
	require.Error(t, err)
	_, err = stores.Waivers.ListContextsByWaiverIDs(ctx, []string{"not-a-uuid"})
	require.Error(t, err)
	_, err = stores.Waivers.ListFindingTargetsByWaiverIDs(ctx, []string{"not-a-uuid"})
	require.Error(t, err)
	_, err = stores.Waivers.ListEvents(ctx, "not-a-uuid")
	require.Error(t, err)
	require.NoError(t, stores.Waivers.Delete(ctx, waiver.ID, project.ID))
	require.ErrorIs(t, stores.Waivers.Delete(ctx, waiver.ID, project.ID), port.ErrNotFound)
	_, err = stores.Artifacts.Delete(ctx, artifact.ID, project.ID)
	require.NoError(t, err)
	_, err = stores.Targets.Delete(ctx, target.ID, project.ID)
	require.NoError(t, err)
	_, err = stores.Environments.Delete(ctx, environment.ID, project.ID)
	require.NoError(t, err)
}
