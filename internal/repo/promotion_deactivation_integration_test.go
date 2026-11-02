//go:build integration

package repo

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// pauseDBTX holds the first statement whose text contains match until release
// is closed, after closing reached. It lets a test stop a transaction between
// two of its statements without changing the code under test.
type pauseDBTX struct {
	tx      pgx.Tx
	match   string
	reached chan struct{}
	release chan struct{}
	once    sync.Once
}

func (p *pauseDBTX) hold(sql string) {
	if strings.Contains(sql, p.match) {
		p.once.Do(func() {
			close(p.reached)
			<-p.release
		})
	}
}

func (p *pauseDBTX) Exec(ctx context.Context, sql string, args ...interface{}) (pgconn.CommandTag, error) {
	p.hold(sql)
	return p.tx.Exec(ctx, sql, args...)
}

func (p *pauseDBTX) Query(ctx context.Context, sql string, args ...interface{}) (pgx.Rows, error) {
	p.hold(sql)
	return p.tx.Query(ctx, sql, args...)
}

func (p *pauseDBTX) QueryRow(ctx context.Context, sql string, args ...interface{}) pgx.Row {
	p.hold(sql)
	return p.tx.QueryRow(ctx, sql, args...)
}

// pausingUsers returns a user port whose transactions pause at match.
func pausingUsers(pool *pgxpool.Pool, match string) (*pgUserPort, chan struct{}, chan struct{}) {
	reached, release := make(chan struct{}), make(chan struct{})
	withTx := func(ctx context.Context, fn func(q *sqlc.Queries) error) error {
		tx, err := pool.Begin(ctx)
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := fn(sqlc.New(&pauseDBTX{tx: tx, match: match, reached: reached, release: release})); err != nil {
			return err
		}
		return tx.Commit(ctx)
	}
	return &pgUserPort{q: sqlc.New(pool), withTx: withTx}, reached, release
}

func waitFor(t *testing.T, ch chan struct{}, what string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(10 * time.Second):
		t.Fatalf("never reached: %s", what)
	}
}

// A promotion of the account to admin of a project that commits after the
// deactivation's last lock run and before its sole-admin query would leave the
// project with one admin who is about to be deactivated by someone else. The
// promotion share-locks the account first, so it waits for the deactivation.
func TestPromotionToAdminWaitsForADeactivationOfTheSameAccount(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}
	newUser(t, repos, "admin@test.com", "admin")

	_, qAdmins := projectWithAdmins(t, repos, ports, 2)
	x := qAdmins[0]
	pID, pAdmins := projectWithAdmins(t, repos, ports, 1)
	w := pAdmins[0]
	_, err := ports.UpsertMember(ctx, pID, x, "member")
	require.NoError(t, err)

	xUsers, xAtList, xGo := pausingUsers(repos.pool, "ListProjectsSoleAdminedBy")
	xErr := make(chan error, 1)
	go func() { _, _, err := xUsers.Deactivate(ctx, x, false); xErr <- err }()
	waitFor(t, xAtList, "x reaches its sole-admin query")

	promoted := make(chan error, 1)
	go func() { _, err := ports.UpsertMember(ctx, pID, x, "admin"); promoted <- err }()
	select {
	case err := <-promoted:
		t.Fatalf("the promotion finished while the deactivation of the same account was open: %v", err)
	case <-time.After(500 * time.Millisecond):
	}

	close(xGo)
	require.NoError(t, <-xErr, "x administers nothing alone, so it is deactivated")
	require.ErrorIs(t, <-promoted, port.ErrNotFound, "a deactivated account is not made an admin")

	// w is still the only admin who can sign in of p.
	_, _, err = (&pgUserPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}).Deactivate(ctx, w, false)
	var sole *port.SoleProjectAdminError
	require.ErrorAs(t, err, &sole)
	left, err := ports.CountAdmins(ctx, pID)
	require.NoError(t, err)
	require.Equal(t, 1, left)
}

func TestPromotingADeactivatedAccountToAdminIsRefusedButMemberIsNot(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	ports := &pgProjectPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}
	users := &pgUserPort{q: sqlc.New(repos.pool), withTx: repos.WithTx}
	newUser(t, repos, "admin@test.com", "admin")
	pID, _ := projectWithAdmins(t, repos, ports, 1)
	gone := newTestUserID(t, repos)
	_, err := users.SetDisabled(ctx, gone, true)
	require.NoError(t, err)

	_, err = ports.UpsertMember(ctx, pID, gone, "admin")
	assert.ErrorIs(t, err, port.ErrNotFound)
	_, err = ports.UpsertMember(ctx, pID, gone, "member")
	assert.NoError(t, err)
	_, err = ports.UpsertMember(ctx, pID, "00000000-0000-4000-8000-000000000001", "member")
	assert.ErrorIs(t, err, port.ErrNotFound, "an unknown account is not found")
}
