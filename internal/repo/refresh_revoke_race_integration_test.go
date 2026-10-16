//go:build integration

package repo

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/port"
)

// rotationGateKey is the advisory lock a test holds to park a rotation.
const rotationGateKey = 7301

// installRotationGate makes every refresh_tokens INSERT wait for the advisory
// lock rotationGateKey. While a test holds it, a rotation stops inside its
// transaction right before it stores the successor: the account row is locked
// and the old token is already marked revoked, but nothing is committed.
func installRotationGate(t *testing.T, repos *Repos) {
	t.Helper()
	ctx := context.Background()
	_, err := repos.pool.Exec(ctx, `CREATE FUNCTION rotation_gate() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN PERFORM pg_advisory_xact_lock_shared(7301); RETURN NEW; END $$`)
	require.NoError(t, err)
	_, err = repos.pool.Exec(ctx, `CREATE TRIGGER rotation_gate BEFORE INSERT ON refresh_tokens
FOR EACH ROW EXECUTE FUNCTION rotation_gate()`)
	require.NoError(t, err)
}

// closeRotationGate takes the advisory lock and returns the function that
// lets the parked rotation go.
func closeRotationGate(t *testing.T, repos *Repos) (open func()) {
	t.Helper()
	ctx := context.Background()
	conn, err := repos.pool.Acquire(ctx)
	require.NoError(t, err)
	_, err = conn.Exec(ctx, "SELECT pg_advisory_lock($1)", rotationGateKey)
	require.NoError(t, err)
	opened := false
	return func() {
		if opened {
			return
		}
		opened = true
		_, _ = conn.Exec(ctx, "SELECT pg_advisory_unlock($1)", rotationGateKey)
		conn.Release()
	}
}

// waitForLockWaiters blocks until n backends wait on a lock, so the test knows
// the rotation and the revoke are both in flight before the gate opens.
func waitForLockWaiters(t *testing.T, repos *Repos, n int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		var waiting int
		require.NoError(t, repos.pool.QueryRow(context.Background(),
			`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`).Scan(&waiting))
		if waiting >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d lock waiters", n)
}

// A thief's rotation is parked before it stores its successor. A revoke of
// that sign-in chain, or of all the account's tokens, starts now. It must wait
// for the rotation to commit and then revoke the successor too; a revoke that
// finishes first leaves the successor alive, and the thief keeps the session.
func TestRevokeWaitsForAnInFlightRotation(t *testing.T) {
	revokes := map[string]func(ctx context.Context, stores *port.Stores, user port.User, familyID string) error{
		"family": func(ctx context.Context, stores *port.Stores, _ port.User, familyID string) error {
			return stores.RefreshTokens.RevokeFamily(ctx, familyID)
		},
		"all of a user's tokens": func(ctx context.Context, stores *port.Stores, user port.User, _ string) error {
			return stores.RefreshTokens.RevokeAllForUser(ctx, user.ID)
		},
	}
	for name, revoke := range revokes {
		t.Run(name, func(t *testing.T) {
			repos, cleanup := setupTestDB(t)
			defer cleanup()
			ctx := context.Background()
			stores := NewPortStores(repos.pool)
			user := newPasswordUser(t, repos, raceOldPassword)
			family := uuid.NewString()
			version, err := stores.Users.TokenVersion(ctx, user.ID)
			require.NoError(t, err)

			// The victim's token was spent by the thief, who now holds the
			// live successor.
			stolen, err := stores.RefreshTokens.Create(ctx, rotationInput(user, family))
			require.NoError(t, err)
			held := rotationInput(user, family)
			require.NoError(t, stores.RefreshTokens.Rotate(ctx, stolen.ID, held, version))
			heldRow, err := stores.RefreshTokens.GetByHash(ctx, held.TokenHash)
			require.NoError(t, err)

			installRotationGate(t, repos)
			openGate := closeRotationGate(t, repos)
			defer openGate()

			next := rotationInput(user, family)
			rotated := make(chan error, 1)
			go func() { rotated <- stores.RefreshTokens.Rotate(ctx, heldRow.ID, next, version) }()
			waitForLockWaiters(t, repos, 1) // the rotation, parked at the insert

			revoked := make(chan error, 1)
			go func() { revoked <- revoke(ctx, stores, user, family) }()
			waitForLockWaiters(t, repos, 2) // the revoke, behind the rotation

			openGate()
			require.NoError(t, <-rotated, "the rotation was under way first and commits")
			require.NoError(t, <-revoked)

			successor, err := stores.RefreshTokens.GetByHash(ctx, next.TokenHash)
			require.NoError(t, err)
			assert.NotNil(t, successor.RevokedAt, "the successor the rotation stored is revoked with the rest")
			assert.Zero(t, liveRefreshTokens(t, repos, user.ID), "no token of the account stays live")
		})
	}
}

// The same race through the use cases: the victim replays the stolen token
// while the thief's refresh of the successor is in flight. The victim is told
// the token was reused and the thief's next refresh fails.
func TestFamilyRevokeRacingAThiefRotationLeavesNoSession(t *testing.T) {
	repos, cleanup := setupTestDB(t)
	defer cleanup()
	ctx := context.Background()
	uc := raceUsecases(t, repos)
	user := newPasswordUser(t, repos, raceOldPassword)
	victim, err := uc.Login(ctx, user.Email, raceOldPassword)
	require.NoError(t, err)
	stolen, err := uc.Refresh(ctx, victim.RefreshToken) // the thief spends the stolen token first
	require.NoError(t, err)

	installRotationGate(t, repos)
	openGate := closeRotationGate(t, repos)
	defer openGate()

	type refreshed struct {
		token string
		err   error
	}
	thief := make(chan refreshed, 1)
	go func() { // the thief's next refresh is in flight
		resp, err := uc.Refresh(ctx, stolen.RefreshToken)
		if err != nil {
			thief <- refreshed{err: err}
			return
		}
		thief <- refreshed{token: resp.RefreshToken}
	}()
	waitForLockWaiters(t, repos, 1)

	replay := make(chan error, 1)
	go func() { _, err := uc.Refresh(ctx, victim.RefreshToken); replay <- err }()
	waitForLockWaiters(t, repos, 2)

	openGate()
	won := <-thief
	require.NoError(t, won.err)
	require.Error(t, <-replay, "the replayed token is refused")

	_, err = uc.Refresh(ctx, won.token)
	require.Error(t, err, "the thief's successor died with the chain")
	assert.Zero(t, liveRefreshTokens(t, repos, user.ID))
}
