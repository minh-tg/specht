//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_ChangePassword walks the signed-in password change against the real
// server: a wrong or weak password changes nothing, and a good one ends every
// other session while the caller stays signed in with a fresh one.
func TestE2E_ChangePassword(t *testing.T) {
	const email = "e2e-viewer@example.com"
	const next = "a-brand-new-password-1"

	// The account is shared with other tests, so put its password back.
	t.Cleanup(func() {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": email, "password": next})
		if status != http.StatusOK {
			return // never changed
		}
		var resp authResponse
		require.NoError(t, json.Unmarshal(raw, &resp))
		doJSON(t, http.MethodPut, "/api/v1/me/password", resp.Token,
			map[string]string{"current_password": next, "new_password": adminPass})
	})

	session := request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
		map[string]string{"email": email, "password": adminPass}, http.StatusOK)

	t.Run("a wrong current password changes nothing and does not sign the person out", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPut, "/api/v1/me/password", session.Token,
			map[string]string{"current_password": "not-the-password", "new_password": next})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "wrong_password", errorCode(t, raw))

		status, _ = doJSON(t, http.MethodGet, "/api/v1/me", session.Token, nil)
		require.Equal(t, http.StatusOK, status, "the session survives a mistyped form")
		login(t, email, adminPass)
	})

	t.Run("the new password follows the registration rules", func(t *testing.T) {
		for name, body := range map[string]map[string]string{
			"too short": {"current_password": adminPass, "new_password": "short"},
			"unchanged": {"current_password": adminPass, "new_password": adminPass},
		} {
			status, raw := doJSON(t, http.MethodPut, "/api/v1/me/password", session.Token, body)
			require.Equal(t, http.StatusBadRequest, status, name+": "+string(raw))
			require.Equal(t, "invalid_password", errorCode(t, raw), name)
		}
		login(t, email, adminPass)
	})

	t.Run("it needs a session", func(t *testing.T) {
		status, _ := doJSON(t, http.MethodPut, "/api/v1/me/password", "",
			map[string]string{"current_password": adminPass, "new_password": next})
		require.Equal(t, http.StatusUnauthorized, status)
	})

	t.Run("a good change ends the other sessions and keeps the caller signed in", func(t *testing.T) {
		other := request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": email, "password": adminPass}, http.StatusOK)

		fresh := request[authResponse](t, http.MethodPut, "/api/v1/me/password", session.Token,
			map[string]string{"current_password": adminPass, "new_password": next}, http.StatusOK)
		require.NotEmpty(t, fresh.Token)
		require.NotEmpty(t, fresh.RefreshToken)

		status, _ := doJSON(t, http.MethodGet, "/api/v1/me", fresh.Token, nil)
		require.Equal(t, http.StatusOK, status, "the caller stays signed in")

		for name, token := range map[string]string{"the session that changed it": session.Token, "another session": other.Token} {
			status, _ = doJSON(t, http.MethodGet, "/api/v1/me", token, nil)
			require.Equal(t, http.StatusUnauthorized, status, name+" ends")
		}
		for name, refresh := range map[string]string{"the old": session.RefreshToken, "another": other.RefreshToken} {
			status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/refresh", "",
				map[string]string{"refresh_token": refresh})
			require.GreaterOrEqual(t, status, 400, name+" refresh token no longer yields a session: "+string(raw))
		}

		status, _ = doJSON(t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": email, "password": adminPass})
		require.Equal(t, http.StatusUnauthorized, status, "the old password stops working")
		login(t, email, next)
	})
}
