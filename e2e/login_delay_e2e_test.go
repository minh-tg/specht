//go:build e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestE2E_LoginDelayAfterRepeatedFailures drives the real server: three
// failed sign-ins for one email start a wait, the next attempt is refused
// with 429 and Retry-After without touching the password check, and another
// account signs in as usual. The email is unknown, which counts the same as
// a known one.
func TestE2E_LoginDelayAfterRepeatedFailures(t *testing.T) {
	email := fmt.Sprintf("delay-%d@example.com", time.Now().UnixNano())
	attempt := func(email, password string) (int, string, string) {
		raw, err := json.Marshal(map[string]string{"email": email, "password": password})
		require.NoError(t, err)
		resp, err := http.Post(baseURL+"/api/v1/auth/login", "application/json", bytes.NewReader(raw))
		require.NoError(t, err)
		defer resp.Body.Close()
		var body apiError
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
		return resp.StatusCode, body.Error.Code, resp.Header.Get("Retry-After")
	}

	for i := range 3 {
		status, code, _ := attempt(email, "wrong-password-1")
		require.Equal(t, http.StatusUnauthorized, status, "attempt %d", i+1)
		require.Equal(t, "login_failed", code)
	}
	status, code, retryAfter := attempt(email, "wrong-password-1")
	require.Equal(t, http.StatusTooManyRequests, status)
	require.Equal(t, "too_many_attempts", code)
	require.Equal(t, "1", retryAfter)

	loginAs := login(t, adminEmail, adminPass)
	require.NotEmpty(t, loginAs, "another account is not slowed down")
}
