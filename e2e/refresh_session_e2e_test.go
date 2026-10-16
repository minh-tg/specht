//go:build e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
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
