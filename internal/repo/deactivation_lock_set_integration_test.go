//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db/sqlc"
)

// The projects a deactivation locks are read when its lock statement starts,
// and the statement can wait on one lock for a while. A promotion of the account
// to admin of another project that commits meanwhile must still be locked,
// otherwise the deactivation and one of that project's other admin's both pass
// the sole-admin check and the project keeps no admin who can sign in.
//
// The two outside transactions only hold locks a membership write or a reader
// could hold; they widen a window that exists without them.
func TestDeactivationLocksAProjectPromotedWhileItWaits(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}
	stores := NewPortStores(repos.pool)
	newUser(t, repos, "admin@test.com", "admin")

	// q: x and z are admins. p: w is the only admin, x is a member.
	qID, qAdmins := projectWithAdmins(t, repos, ports, 2)
	x := qAdmins[0]
	pID, pAdmins := projectWithAdmins(t, repos, ports, 1)
	w := pAdmins[0]
	_, err := ports.UpsertMember(ctx, pID, x, "member")
	require.NoError(t, err)

	waitBlocked := func(query string) {
		t.Helper()
		require.Eventually(t, func() bool {
			var n int
			err := repos.pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' AND query LIKE $1`, "%"+query+"%").Scan(&n)
			return err == nil && n > 0
		}, 10*time.Second, 20*time.Millisecond, "a statement is waiting: %s", query)
	}

	holdQ, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	_, err = holdQ.Exec(ctx, `SELECT id FROM projects WHERE id = $1 FOR NO KEY UPDATE`, uuid.MustParse(qID))
	require.NoError(t, err)

	xErr := make(chan error, 1)
	go func() {
		_, _, err := stores.Users.Deactivate(ctx, x, false)
		xErr <- err
	}()
	waitBlocked("LockProjectsAdministeredBy")

	_, err = ports.UpsertMember(ctx, pID, x, "admin")
	require.NoError(t, err, "x becomes an admin of p while its deactivation waits")

	holdW, err := repos.pool.Begin(ctx)
	require.NoError(t, err)
	_, err = holdW.Exec(ctx, `SELECT id FROM users WHERE id = $1 FOR SHARE`, uuid.MustParse(w))
	require.NoError(t, err)

	wErr := make(chan error, 1)
	go func() {
		_, _, err := stores.Users.Deactivate(ctx, w, false)
		wErr <- err
	}()
	waitBlocked("SetUserDisabled")

	require.NoError(t, holdQ.Commit(ctx))
	time.Sleep(500 * time.Millisecond)
	require.NoError(t, holdW.Commit(ctx))

	errX, errW := <-xErr, <-wErr
	left, err := ports.CountAdmins(ctx, pID)
	require.NoError(t, err)
	require.Equalf(t, 1, left, "p kept %d admins who can sign in (x: %v, w: %v)", left, errX, errW)
}
