//go:build integration

package repo

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestUserID(t *testing.T, repos *Repos) string {
	t.Helper()
	user, err := repos.Users.Create(context.Background(), uuid.NewString()+"@test.com",
		pgtype.Text{Valid: false}, pgtype.Text{Valid: true, String: "unused-hash"})
	require.NoError(t, err)
	return uuid.UUID(user.ID.Bytes).String()
}

// projectWithAdmins creates a project whose only members are n admins.
func projectWithAdmins(t *testing.T, repos *Repos, ports *pgProjectPort, n int) (string, []string) {
	t.Helper()
	project := createTestProject(t, repos)
	projectID := uuid.UUID(project.ID.Bytes).String()
	admins := make([]string, n)
	for i := range admins {
		admins[i] = newTestUserID(t, repos)
		_, err := ports.UpsertMember(context.Background(), projectID, admins[i], "admin")
		require.NoError(t, err)
	}
	return projectID, admins
}

func TestProjectMembers_LastAdminIsProtected(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}

	projectID, admins := projectWithAdmins(t, repos, ports, 1)
	only := admins[0]

	assert.ErrorIs(t, ports.DeleteMember(ctx, projectID, only), port.ErrLastAdmin)
	_, err := ports.UpsertMember(ctx, projectID, only, "manager")
	assert.ErrorIs(t, err, port.ErrLastAdmin)
	m, err := ports.GetMember(ctx, projectID, only)
	require.NoError(t, err)
	assert.Equal(t, "admin", m.Role, "a refused demotion must leave the role untouched")

	_, err = ports.UpsertMember(ctx, projectID, only, "admin")
	require.NoError(t, err, "re-asserting admin is not a demotion")

	second := newTestUserID(t, repos)
	_, err = ports.UpsertMember(ctx, projectID, second, "admin")
	require.NoError(t, err)
	require.NoError(t, ports.DeleteMember(ctx, projectID, only), "a second admin makes the first removable")
	assert.ErrorIs(t, ports.DeleteMember(ctx, projectID, second), port.ErrLastAdmin)

	member := newTestUserID(t, repos)
	_, err = ports.UpsertMember(ctx, projectID, member, "member")
	require.NoError(t, err)
	require.NoError(t, ports.DeleteMember(ctx, projectID, member), "removing a non-admin is unaffected")

	_, err = ports.UpsertMember(ctx, uuid.NewString(), second, "admin")
	assert.ErrorIs(t, err, port.ErrNotFound, "an unknown project is reported as not found")
}

func TestProjectMembers_UnknownUserIsNotFound(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}

	projectID, _ := projectWithAdmins(t, repos, ports, 1)
	_, err := ports.UpsertMember(context.Background(), projectID, uuid.NewString(), "member")
	assert.ErrorIs(t, err, port.ErrNotFound, "granting a user that does not exist is reported as not found")
}

func TestProjectMembers_ConcurrentAdminRemovalsKeepOneAdmin(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}

	const rounds = 25
	for round := range rounds {
		projectID, admins := projectWithAdmins(t, repos, ports, 2)
		ops := []func() error{
			func() error { return ports.DeleteMember(ctx, projectID, admins[0]) },
			func() error { return ports.DeleteMember(ctx, projectID, admins[1]) },
		}
		if round%2 == 1 {
			ops[1] = func() error {
				_, err := ports.UpsertMember(ctx, projectID, admins[1], "manager")
				return err
			}
		}

		start := make(chan struct{})
		errs := make([]error, len(ops))
		var wg sync.WaitGroup
		for i, op := range ops {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				errs[i] = op()
			}()
		}
		close(start)
		wg.Wait()

		lost := 0
		for _, err := range errs {
			if err != nil {
				assert.ErrorIs(t, err, port.ErrLastAdmin, "round %d", round)
				lost++
			}
		}
		assert.Equal(t, 1, lost, "round %d: exactly one of two concurrent writes must lose", round)
		admins2, err := ports.CountAdmins(ctx, projectID)
		require.NoError(t, err)
		assert.Equal(t, 1, admins2, "round %d: the project must keep one admin", round)
	}
}

func TestProjectMembers_WritesWaitForTheProjectLock(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}

	projectID, admins := projectWithAdmins(t, repos, ports, 2)
	pid, err := parseID(projectID)
	require.NoError(t, err)

	tx, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = sqlc.New(tx).LockProjectForMembership(ctx, pid)
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() { done <- ports.DeleteMember(ctx, projectID, admins[0]) }()

	select {
	case err := <-done:
		t.Fatalf("DeleteMember returned (%v) while another transaction held the project lock", err)
	case <-time.After(500 * time.Millisecond):
	}

	require.NoError(t, tx.Rollback(ctx))
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("DeleteMember did not resume after the lock was released")
	}
}
