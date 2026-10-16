//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func tokenHashOf(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func refreshConn(t *testing.T) *pgx.Conn {
	t.Helper()
	conn, err := pgx.Connect(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return conn
}

// TestE2E_RefreshStopsAtTheAbsoluteSessionLifetime ages a sign-in in the
// database and checks the server ends it: a session 29 days old still rotates
// and its new token is cut to the days left, one past 30 days is refused with
// the answer an expired token gets, and rotation never moves the start forward.
func TestE2E_RefreshStopsAtTheAbsoluteSessionLifetime(t *testing.T) {
	conn := refreshConn(t)
	ctx := context.Background()
	age := func(raw string, by time.Duration) {
		_, err := conn.Exec(ctx, "UPDATE refresh_tokens SET family_started_at = now() - $2::interval WHERE token_hash = $1",
			tokenHashOf(raw), by.String())
		require.NoError(t, err)
	}

	t.Run("a session with a day left rotates into a token that ends with it", func(t *testing.T) {
		s := registerPerson(t, "session-edge")
		age(s.RefreshToken, 29*24*time.Hour)

		next := request[authResponse](t, http.MethodPost, "/api/v1/auth/refresh", "",
			map[string]string{"refresh_token": s.RefreshToken}, http.StatusOK)

		var started, expires time.Time
		require.NoError(t, conn.QueryRow(ctx, "SELECT family_started_at, expires_at FROM refresh_tokens WHERE token_hash = $1",
			tokenHashOf(next.RefreshToken)).Scan(&started, &expires))
		require.WithinDuration(t, time.Now().Add(-29*24*time.Hour), started, time.Minute, "the original sign-in time is kept")
		require.WithinDuration(t, started.Add(30*24*time.Hour), expires, time.Second, "the token ends with the session, not a week out")
	})

	t.Run("a session past 30 days is refused like an expired token", func(t *testing.T) {
		s := registerPerson(t, "session-over")
		age(s.RefreshToken, 31*24*time.Hour)

		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/refresh", "", map[string]string{"refresh_token": s.RefreshToken})
		require.Equal(t, http.StatusUnauthorized, status, string(raw))
		require.Equal(t, "refresh_failed", errorCode(t, raw))
	})
}

// TestE2E_RefreshReuse covers theft detection against the real server. A token
// is single-use: any second use, however soon after the first, revokes that
// sign-in and leaves the user's other sign-ins alone.
func TestE2E_RefreshReuse(t *testing.T) {
	refresh := func(raw string) (int, []byte) {
		return doJSON(t, http.MethodPost, "/api/v1/auth/refresh", "", map[string]string{"refresh_token": raw})
	}
	signInTwice := func(label string) (laptop, phone authResponse) {
		time.Sleep(time.Second) // keep each subtest inside the anonymous bucket
		email := label + "-" + randomHex(4) + "@example.com"
		request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
			map[string]string{"email": email, "password": adminPass}, http.StatusCreated)
		signIn := func() authResponse {
			return request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
				map[string]string{"email": email, "password": adminPass}, http.StatusOK)
		}
		return signIn(), signIn()
	}

	// The anonymous auth routes share a per-address bucket of 10 requests a
	// second (burst 20) whatever RATE_LIMIT_* says, so let it fill first.
	time.Sleep(2500 * time.Millisecond)
	// The next test registers people straight away; leave it a full bucket.
	t.Cleanup(func() { time.Sleep(2500 * time.Millisecond) })

	t.Run("a concurrent double refresh revokes that sign-in", func(t *testing.T) {
		laptop, phone := signInTwice("reuse-race")
		const n = 4
		var mu sync.Mutex
		var winner string
		var wg sync.WaitGroup
		codes := make([]int, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				status, raw := refresh(laptop.RefreshToken)
				codes[i] = status
				if status == http.StatusOK {
					var out authResponse
					require.NoError(t, json.Unmarshal(raw, &out))
					mu.Lock()
					winner = out.RefreshToken
					mu.Unlock()
				} else {
					require.Equal(t, "refresh_reused", errorCode(t, raw))
				}
			}(i)
		}
		wg.Wait()
		wins := 0
		for _, c := range codes {
			if c == http.StatusOK {
				wins++
			}
		}
		require.Equal(t, 1, wins, "exactly one refresh wins: %v", codes)

		status, raw := refresh(winner)
		require.Equal(t, http.StatusUnauthorized, status, "the winner's successor is revoked with the chain: %s", raw)
		status, raw = refresh(phone.RefreshToken)
		require.Equal(t, http.StatusOK, status, "the phone's sign-in is a separate family and survives: %s", raw)
	})

	t.Run("a replay right after the rotation revokes that sign-in only", func(t *testing.T) {
		laptop, phone := signInTwice("reuse-family")
		rotated := request[authResponse](t, http.MethodPost, "/api/v1/auth/refresh", "",
			map[string]string{"refresh_token": laptop.RefreshToken}, http.StatusOK)

		status, raw := refresh(laptop.RefreshToken)
		require.Equal(t, http.StatusUnauthorized, status)
		require.Equal(t, "refresh_reused", errorCode(t, raw))

		status, _ = refresh(rotated.RefreshToken)
		require.Equal(t, http.StatusUnauthorized, status, "the laptop's chain is revoked")
		status, raw = refresh(phone.RefreshToken)
		require.Equal(t, http.StatusOK, status, "the phone's sign-in is a separate family and survives: %s", raw)
	})

	t.Run("signing out with a rotated token revokes that sign-in only", func(t *testing.T) {
		laptop, phone := signInTwice("reuse-logout")
		rotated := request[authResponse](t, http.MethodPost, "/api/v1/auth/refresh", "",
			map[string]string{"refresh_token": laptop.RefreshToken}, http.StatusOK)

		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/logout", "", map[string]string{"refresh_token": laptop.RefreshToken})
		require.Equal(t, http.StatusNoContent, status, string(raw))

		status, _ = refresh(rotated.RefreshToken)
		require.Equal(t, http.StatusUnauthorized, status, "the stale logout ran the reuse path and revoked the successor")
		status, raw = refresh(phone.RefreshToken)
		require.Equal(t, http.StatusOK, status, "the phone's sign-in survives: %s", raw)
	})
}

// TestE2E_DeadRefreshTokensArePruned ages rows in the database and waits for
// the sweeper (every second in this suite) to delete them.
func TestE2E_DeadRefreshTokensArePruned(t *testing.T) {
	conn := refreshConn(t)
	ctx := context.Background()
	exists := func(raw string) bool {
		var n int
		require.NoError(t, conn.QueryRow(ctx, "SELECT count(*) FROM refresh_tokens WHERE token_hash = $1", tokenHashOf(raw)).Scan(&n))
		return n == 1
	}
	expired, revokedOld, revokedNew, live := registerPerson(t, "prune-a"), registerPerson(t, "prune-b"),
		registerPerson(t, "prune-c"), registerPerson(t, "prune-d")
	set := func(column string, raw string, ago string) {
		_, err := conn.Exec(ctx, "UPDATE refresh_tokens SET "+column+" = now() - $2::interval WHERE token_hash = $1", tokenHashOf(raw), ago)
		require.NoError(t, err)
	}
	set("expires_at", expired.RefreshToken, "1 minute")
	set("revoked_at", revokedOld.RefreshToken, "8 days")
	set("revoked_at", revokedNew.RefreshToken, "1 day")

	require.Eventually(t, func() bool {
		return !exists(expired.RefreshToken) && !exists(revokedOld.RefreshToken)
	}, 15*time.Second, 250*time.Millisecond, "expired and long-revoked rows are deleted")
	require.True(t, exists(revokedNew.RefreshToken), "a token revoked a day ago is kept for reuse detection")
	require.True(t, exists(live.RefreshToken), "a live token is never pruned")
}
