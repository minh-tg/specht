//go:build integration

package repo

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errPeerDenied = errors.New("peer denied")

// refuseAdminTarget is the peer rule a manager's write is held to: the row it
// replaces must not be an admin's.
func refuseAdminTarget(existing *port.ProjectMember) error {
	if existing != nil && existing.Role == "admin" {
		return errPeerDenied
	}
	return nil
}

// The check of a checked write runs under the membership lock, on the row as
// the lock holder left it. Writer A promotes a member and holds the lock until
// told to commit; writer B's checked write of the same person queues behind
// it, and so judges the admin row, not the member row that was there before A.
func TestProjectMembers_CheckedWritesJudgeTheRowUnderTheLock(t *testing.T) {
	for _, tc := range []struct {
		name  string
		write func(ctx context.Context, p *pgProjectPort, projectID, userID string, check port.MemberCheck) error
	}{
		{"upsert", func(ctx context.Context, p *pgProjectPort, projectID, userID string, check port.MemberCheck) error {
			_, err := p.UpsertMemberChecked(ctx, projectID, userID, "manager", check)
			return err
		}},
		{"delete", func(ctx context.Context, p *pgProjectPort, projectID, userID string, check port.MemberCheck) error {
			return p.DeleteMemberChecked(ctx, projectID, userID, check)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repos, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := context.Background()
			ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}

			projectID, _ := projectWithAdmins(t, repos, ports, 1)
			target := newTestUserID(t, repos)
			_, err := ports.UpsertMember(ctx, projectID, target, "member")
			require.NoError(t, err)

			inLock := make(chan struct{})
			release := make(chan struct{})
			promoted := make(chan error, 1)
			go func() {
				_, err := ports.UpsertMemberChecked(ctx, projectID, target, "admin", func(*port.ProjectMember) error {
					close(inLock)
					<-release
					return nil
				})
				promoted <- err
			}()
			<-inLock

			var sawRole string
			racer := make(chan error, 1)
			go func() {
				racer <- tc.write(ctx, ports, projectID, target, func(existing *port.ProjectMember) error {
					if existing != nil {
						sawRole = existing.Role
					}
					return refuseAdminTarget(existing)
				})
			}()
			select {
			case err := <-racer:
				t.Fatalf("the second write ran while the first held the lock (%v)", err)
			case <-time.After(300 * time.Millisecond):
			}

			close(release)
			require.NoError(t, <-promoted)
			assert.ErrorIs(t, <-racer, errPeerDenied)
			assert.Equal(t, "admin", sawRole, "the check saw the promoted row")
			m, err := ports.GetMember(ctx, projectID, target)
			require.NoError(t, err)
			assert.Equal(t, "admin", m.Role, "the refused write changed nothing")
		})
	}
}

func TestProjectMembers_CheckSeesNilForAMissingRow(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}
	projectID, _ := projectWithAdmins(t, repos, ports, 1)
	stranger := newTestUserID(t, repos)

	missing := errors.New("no such member")
	err := ports.DeleteMemberChecked(ctx, projectID, stranger, func(existing *port.ProjectMember) error {
		if existing == nil {
			return missing
		}
		return nil
	})
	assert.ErrorIs(t, err, missing)

	var seenNil bool
	_, err = ports.UpsertMemberChecked(ctx, projectID, stranger, "member", func(existing *port.ProjectMember) error {
		seenNil = existing == nil
		return nil
	})
	require.NoError(t, err)
	assert.True(t, seenNil)
	m, err := ports.GetMember(ctx, projectID, stranger)
	require.NoError(t, err)
	assert.Equal(t, "member", m.Role)
}

// A slug with no project is port.ErrNotFound, not the driver's no-rows error,
// so the use cases' not-found handling matches the real store.
func TestProjectGetBySlug_MissingIsNotFound(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}

	_, err := ports.GetBySlug(context.Background(), "no-such-project")
	assert.ErrorIs(t, err, port.ErrNotFound)
}
