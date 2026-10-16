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

// TestE2E_RefreshReuse covers theft detection against the real server: a
// concurrent double refresh keeps the winner's session, and a replay after the
// grace window revokes that sign-in only.
func TestE2E_RefreshReuse(t *testing.T) {
	conn := refreshConn(t)
	ctx := context.Background()
	refresh := func(raw string) (int, []byte) {
		return doJSON(t, http.MethodPost, "/api/v1/auth/refresh", "", map[string]string{"refresh_token": raw})
	}

	// The anonymous auth routes share a per-address bucket of 10 requests a
	// second (burst 20) whatever RATE_LIMIT_* says, so let it fill first.
	time.Sleep(2500 * time.Millisecond)

	t.Run("a concurrent double refresh keeps the winner's session", func(t *testing.T) {
		s := registerPerson(t, "reuse-race")
		const n = 4
		var mu sync.Mutex
		var winner string
		var wg sync.WaitGroup
		codes := make([]int, n)
		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				status, raw := refresh(s.RefreshToken)
				codes[i] = status
				if status == http.StatusOK {
					var out authResponse
					require.NoError(t, json.Unmarshal(raw, &out))
					mu.Lock()
					winner = out.RefreshToken
					mu.Unlock()
				} else {
					require.Equal(t, "refresh_reused", errorCode(t, raw), "a loser must not look like a revoked token")
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
		require.Equal(t, http.StatusOK, status, "the winner keeps its session: %s", raw)
	})

	t.Run("a replay after the grace window revokes that sign-in only", func(t *testing.T) {
		time.Sleep(time.Second)
		email := "reuse-family-" + randomHex(4) + "@example.com"
		request[authResponse](t, http.MethodPost, "/api/v1/auth/register", "",
			map[string]string{"email": email, "password": adminPass}, http.StatusCreated)
		signIn := func() authResponse {
			return request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
				map[string]string{"email": email, "password": adminPass}, http.StatusOK)
		}
		laptop, phone := signIn(), signIn()
		rotated := request[authResponse](t, http.MethodPost, "/api/v1/auth/refresh", "",
			map[string]string{"refresh_token": laptop.RefreshToken}, http.StatusOK)

		_, err := conn.Exec(ctx, "UPDATE refresh_tokens SET revoked_at = now() - interval '1 minute' WHERE token_hash = $1",
			tokenHashOf(laptop.RefreshToken))
		require.NoError(t, err)

		status, raw := refresh(laptop.RefreshToken)
		require.Equal(t, http.StatusUnauthorized, status)
		require.Equal(t, "refresh_failed", errorCode(t, raw))

		status, _ = refresh(rotated.RefreshToken)
		require.Equal(t, http.StatusUnauthorized, status, "the laptop's chain is revoked")
		status, raw = refresh(phone.RefreshToken)
		require.Equal(t, http.StatusOK, status, "the phone's sign-in is a separate family and survives: %s", raw)
	})
}
