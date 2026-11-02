//go:build integration

package repo

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// pausingProjects returns a project port whose transactions pause at match.
func pausingProjects(pool *pgxpool.Pool, match string) (*pgProjectPort, chan struct{}, chan struct{}) {
	users, reached, release := pausingUsers(pool, match)
	return &pgProjectPort{q: users.q, withTx: users.withTx}, reached, release
}

// disabledProjectAdmins counts admin rows held by deactivated accounts.
func disabledProjectAdmins(t *testing.T, repos *Repos) int {
	t.Helper()
	var n int
	require.NoError(t, repos.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM project_members pm JOIN users u ON u.id = pm.user_id
		WHERE pm.role = 'admin' AND u.disabled_at IS NOT NULL`).Scan(&n))
	return n
}

func projectInput(slug, adminID string) port.CreateProjectInput {
	return port.CreateProjectInput{Slug: slug, Name: slug, DeploymentThreshold: "high", AdminID: adminID}
}

func TestCreateProject_MakesTheCreatorItsAdmin(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}
	creator := newUser(t, repos, "creator@test.com", "admin")

	p, err := ports.Create(ctx, projectInput("made", creator.ID))
	require.NoError(t, err)
	member, err := ports.GetMember(ctx, p.ID, creator.ID)
	require.NoError(t, err)
	assert.Equal(t, "admin", member.Role)

	_, err = ports.Create(ctx, projectInput("made", creator.ID))
	require.ErrorIs(t, err, port.ErrSlugTaken)
}

func TestCreateProject_RefusesADeactivatedCreatorAndWritesNothing(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "other@test.com", "admin")
	creator := newUser(t, repos, "creator@test.com", "admin")
	_, err := stores.Users.SetDisabled(ctx, creator.ID, true)
	require.NoError(t, err)

	_, err = stores.Projects.Create(ctx, projectInput("refused", creator.ID))
	require.ErrorIs(t, err, port.ErrAccountDeactivated)
	_, err = stores.Projects.GetBySlug(ctx, "refused")
	require.ErrorIs(t, err, port.ErrNotFound, "no project without its admin")

	_, err = stores.Projects.Create(ctx, projectInput("nobody", "00000000-0000-0000-0000-00000000dead"))
	require.ErrorIs(t, err, port.ErrNotFound)
}

// A deactivation that holds the creator's row makes the create wait, and the
// create then refuses: no project gets the deactivated account as its admin.
func TestCreateProject_WaitsForADeactivationOfTheCreator(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	newUser(t, repos, "other@test.com", "admin")
	creator := newUser(t, repos, "creator@test.com", "admin")
	ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}

	users, atList, release := pausingUsers(repos.pool, "ListProjectsSoleAdminedBy")
	deactivated := make(chan error, 1)
	go func() { _, _, err := users.Deactivate(ctx, creator.ID, false); deactivated <- err }()
	waitFor(t, atList, "the deactivation holds the creator's row")

	created := make(chan error, 1)
	go func() { _, err := ports.Create(ctx, projectInput("raced", creator.ID)); created <- err }()
	select {
	case err := <-created:
		t.Fatalf("the create finished while the deactivation held the creator: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	close(release)
	require.NoError(t, <-deactivated)
	require.ErrorIs(t, <-created, port.ErrAccountDeactivated)
	_, err := ports.GetBySlug(ctx, "raced")
	require.ErrorIs(t, err, port.ErrNotFound)
	assert.Zero(t, disabledProjectAdmins(t, repos))
}

// A create that holds the creator's row makes the deactivation wait, and the
// deactivation then sees the new project the creator is the only admin of.
func TestCreateProject_ADeactivationAfterItSeesTheNewProject(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "other@test.com", "admin")
	creator := newUser(t, repos, "creator@test.com", "admin")

	ports, atInsert, release := pausingProjects(repos.pool, "UpsertProjectMember")
	created := make(chan error, 1)
	go func() { _, err := ports.Create(ctx, projectInput("first", creator.ID)); created <- err }()
	waitFor(t, atInsert, "the create holds the creator's row")

	deactivated := make(chan error, 1)
	go func() { _, _, err := stores.Users.Deactivate(ctx, creator.ID, false); deactivated <- err }()
	select {
	case err := <-deactivated:
		t.Fatalf("the deactivation finished while the create held the creator: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	close(release)
	require.NoError(t, <-created)
	var sole *port.SoleProjectAdminError
	require.ErrorAs(t, <-deactivated, &sole, "the new project is found")
	assert.Equal(t, []string{"first"}, sole.Projects)
	assert.Zero(t, disabledProjectAdmins(t, repos))
}

// Creates and deactivations of the same accounts run at once. Whatever the
// order, no project ends with an admin row for a deactivated account.
func TestCreateProject_RacesWithDeactivationLeaveNoDisabledAdmin(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "other@test.com", "admin")

	for i := range 20 {
		creator := newUser(t, repos, fmt.Sprintf("creator-%d@test.com", i), "admin")
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := stores.Projects.Create(ctx, projectInput(fmt.Sprintf("race-%d", i), creator.ID))
			if err != nil {
				assert.ErrorIs(t, err, port.ErrAccountDeactivated)
			}
		}()
		go func() {
			defer wg.Done()
			_, _, err := stores.Users.Deactivate(ctx, creator.ID, false)
			if err != nil {
				var sole *port.SoleProjectAdminError
				assert.ErrorAs(t, err, &sole)
			}
		}()
		wg.Wait()
	}
	assert.Zero(t, disabledProjectAdmins(t, repos))
}
