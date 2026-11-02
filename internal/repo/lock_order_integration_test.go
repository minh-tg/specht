//go:build integration

package repo

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

func isDeadlock(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "40P01"
}

// Accepting an invite holds the creator's row and inserts the invitee's member
// row, whose foreign key check needs the invitee's row. A deactivation locks the
// active admins in id order. With the creator and the invitee both admins, the
// two used to hold one row each and wait for the other. The accept now locks
// both accounts in id order before anything else, so one waits for the other.
//
// The accept is stopped right after it has locked its accounts and before it
// claims the invite, so the deactivation runs in the middle of it. The ids are
// random, so each round has a fresh chance to put the rows in the order that
// used to deadlock.
func TestInviteAcceptAndDeactivationDoNotDeadlock(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)

	for round := 0; round < 12; round++ {
		creator := newUser(t, repos, fmt.Sprintf("creator-%d@test.com", round), "admin")
		invitee := newUser(t, repos, fmt.Sprintf("invitee-%d@test.com", round), "admin")
		target := newUser(t, repos, fmt.Sprintf("target-%d@test.com", round), "admin")
		project := createTestProject(t, repos)
		projectID := uuid.UUID(project.ID.Bytes).String()
		token := fmt.Sprintf("lock-order-%d", round)
		_, err := stores.Invites.Create(ctx, port.NewInvite{
			TokenHash: hashOf(token), ProjectID: projectID, Role: "member",
			CreatedBy: creator.ID, ExpiresAt: time.Now().Add(time.Hour),
		})
		require.NoError(t, err)

		reached, release := make(chan struct{}), make(chan struct{})
		withTx := func(ctx context.Context, fn func(q *sqlc.Queries) error) error {
			tx, err := repos.pool.Begin(ctx)
			if err != nil {
				return err
			}
			defer func() { _ = tx.Rollback(ctx) }()
			p := &pauseDBTX{tx: tx, match: "ClaimInvite", reached: reached, release: release}
			if err := fn(sqlc.New(p)); err != nil {
				return err
			}
			return tx.Commit(ctx)
		}
		invites := &pgInvitePort{q: sqlc.New(repos.pool), withTx: withTx}

		var accepted, deactivated error
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, accepted = invites.AcceptAsUser(ctx, hashOf(token), invitee.ID)
		}()
		waitFor(t, reached, "the accept stops after locking its accounts")

		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, deactivated = stores.Users.Deactivate(ctx, target.ID, true)
		}()
		time.Sleep(200 * time.Millisecond) // the deactivation is now waiting or done
		close(release)
		wg.Wait()

		assert.Falsef(t, isDeadlock(accepted) || isDeadlock(deactivated),
			"round %d: accept: %v, deactivate: %v", round, accepted, deactivated)
		require.NoErrorf(t, accepted, "round %d", round)
		require.NoErrorf(t, deactivated, "round %d", round)
	}
}

// Two admins demoted at the same time must leave one: each demotion locks the
// active admins and counts them again once it holds the locks.
func TestConcurrentDemotionsKeepAnAdmin(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	stores := NewPortStores(repos.pool)

	for round := 0; round < 25; round++ {
		a := newUser(t, repos, fmt.Sprintf("a-%d@test.com", round), "admin")
		b := newUser(t, repos, fmt.Sprintf("b-%d@test.com", round), "admin")
		// Earlier rounds' admins stay admins; demote them out of the way so
		// this round's two are the only ones.
		_, err := repos.pool.Exec(ctx, `UPDATE users SET role = 'member' WHERE role = 'admin' AND id NOT IN ($1, $2)`, a.ID, b.ID)
		require.NoError(t, err)

		errs := make([]error, 2)
		var wg sync.WaitGroup
		start := make(chan struct{})
		for i, id := range []string{a.ID, b.ID} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, errs[i] = stores.Users.ChangeRole(ctx, id, "member")
			}()
		}
		close(start)
		wg.Wait()

		lost := 0
		for _, err := range errs {
			if err != nil {
				require.ErrorIsf(t, err, port.ErrLastGlobalAdmin, "round %d", round)
				lost++
			}
		}
		assert.Equalf(t, 1, lost, "round %d: exactly one of two concurrent demotions must lose", round)
		var admins int
		require.NoError(t, repos.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE role = 'admin' AND disabled_at IS NULL`).Scan(&admins))
		require.Equalf(t, 1, admins, "round %d: one admin must remain", round)
	}
}
