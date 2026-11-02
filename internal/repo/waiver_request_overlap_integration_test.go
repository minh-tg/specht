//go:build integration

package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

func pendingRequestFor(projectID, requester string, findingIDs ...string) port.CreateWaiverInput {
	targets := make([]port.WaiverFindingTarget, len(findingIDs))
	for i, id := range findingIDs {
		targets[i] = port.WaiverFindingTarget{FindingID: id}
	}
	now := time.Now()
	return port.CreateWaiverInput{
		ProjectID:   projectID,
		Name:        "Waiver request",
		Enabled:     true,
		Status:      "pending",
		Reason:      "needed for the release",
		RequestedBy: &requester,
		RequestedAt: &now,
		Targets:     targets,
		Event:       port.WaiverEventInput{EventType: "requested", ActorID: &requester, Metadata: json.RawMessage(`{}`)},
	}
}

func newWaiverRequestFinding(t *testing.T, stores *port.Stores, projectID, fingerprint string) string {
	t.Helper()
	now := time.Now().UTC()
	finding, err := stores.Findings.Upsert(context.Background(), port.UpsertFindingInput{
		ProjectID: projectID, FindingKind: "sca", Fingerprint: fingerprint, Title: fingerprint,
		Severity: "high", SeverityRank: 3, Score: 8, FirstSeen: now, LastSeen: now,
	})
	require.NoError(t, err)
	return finding.ID
}

// Concurrent requests for one finding leave one pending request: the others
// find it once the project lock is theirs.
func TestWaiverRequest_ConcurrentRequestsForOneFindingStayOne(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	requester := newUser(t, repos, "requester@test.com", "member")
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "waiver-overlap", Name: "Overlap", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	findingID := newWaiverRequestFinding(t, stores, project.ID, "overlap-finding")

	const callers = 8
	var wg sync.WaitGroup
	errs := make([]error, callers)
	start := make(chan struct{})
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = stores.Waivers.CreateWithDetails(ctx, pendingRequestFor(project.ID, requester.ID, findingID))
		}()
	}
	close(start)
	wg.Wait()

	created, refused := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			created++
		case errors.Is(err, port.ErrWaiverRequestExists):
			refused++
		default:
			require.NoError(t, err)
		}
	}
	assert.Equal(t, 1, created, fmt.Sprintf("errors: %v", errs))
	assert.Equal(t, callers-1, refused)
	all, err := stores.Waivers.List(ctx, project.ID)
	require.NoError(t, err)
	assert.Len(t, all, 1)
}

// A decided request no longer blocks a new one, and a request for another
// finding is unaffected.
func TestWaiverRequest_OnlyPendingRequestsBlockAnother(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	requester := newUser(t, repos, "requester2@test.com", "member")
	reviewer := newUser(t, repos, "reviewer@test.com", "admin")
	project, err := stores.Projects.Create(ctx, port.CreateProjectInput{
		Slug: "waiver-decided", Name: "Decided", DeploymentThreshold: "high", Settings: []byte("{}"),
	})
	require.NoError(t, err)
	first := newWaiverRequestFinding(t, stores, project.ID, "first-finding")
	second := newWaiverRequestFinding(t, stores, project.ID, "second-finding")

	pending, err := stores.Waivers.CreateWithDetails(ctx, pendingRequestFor(project.ID, requester.ID, first))
	require.NoError(t, err)
	_, err = stores.Waivers.CreateWithDetails(ctx, pendingRequestFor(project.ID, requester.ID, second, first))
	assert.ErrorIs(t, err, port.ErrWaiverRequestExists, "a request naming a pending finding is refused")
	_, err = stores.Waivers.CreateWithDetails(ctx, pendingRequestFor(project.ID, requester.ID, second))
	require.NoError(t, err, "another finding is free")

	_, err = stores.Waivers.Decide(ctx, pending.ID, project.ID, port.WaiverDecision{
		Status: "rejected", ActorID: reviewer.ID,
		Event: port.WaiverEventInput{EventType: "rejected", ActorID: &reviewer.ID, Metadata: json.RawMessage(`{}`)},
	})
	require.NoError(t, err)
	_, err = stores.Waivers.CreateWithDetails(ctx, pendingRequestFor(project.ID, requester.ID, first))
	assert.NoError(t, err, "a rejected request does not block a new one")
}
