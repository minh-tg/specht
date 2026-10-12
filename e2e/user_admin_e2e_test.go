//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type adminUserRow struct {
	ID         string  `json:"id"`
	Email      string  `json:"email"`
	Role       string  `json:"role"`
	Disabled   bool    `json:"disabled"`
	DisabledAt *string `json:"disabled_at"`
}

// TestE2E_UserDeactivationAndRoleChange walks the account controls an admin
// uses when someone leaves or changes duties: a deactivated person is locked
// out at once on every path, nothing is deleted, and reactivation restores
// the account. A role change reaches sessions that are already open.
func TestE2E_UserDeactivationAndRoleChange(t *testing.T) {
	loginResp := request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
		map[string]string{"email": "e2e-viewer@example.com", "password": adminPass}, http.StatusOK)
	userToken := loginResp.Token
	me := request[userProfile](t, http.MethodGet, "/api/v1/me", userToken, nil, http.StatusOK)
	adminMe := request[userProfile](t, http.MethodGet, "/api/v1/me", adminToken, nil, http.StatusOK)
	base := "/api/v1/users/" + me.ID

	// Whatever happens below, leave the shared account usable for other tests.
	t.Cleanup(func() {
		doJSON(t, http.MethodPost, base+"/reactivate", adminToken, nil)
		doJSON(t, http.MethodPut, base+"/role", adminToken, map[string]string{"role": "member"})
	})

	t.Run("only a global admin may use the controls", func(t *testing.T) {
		for _, call := range []struct{ method, path string }{
			{http.MethodPut, base + "/role"},
			{http.MethodPost, base + "/deactivate"},
			{http.MethodPost, base + "/reactivate"},
		} {
			status, _ := doJSON(t, call.method, call.path, userToken, map[string]string{"role": "admin"})
			require.Equal(t, http.StatusForbidden, status, call.method+" "+call.path)
		}
	})

	t.Run("an admin cannot deactivate themselves", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/users/"+adminMe.ID+"/deactivate", adminToken, nil)
		require.Equal(t, http.StatusConflict, status, string(raw))
		require.Equal(t, "cannot_deactivate_self", errorCode(t, raw))
	})

	t.Run("validation and unknown users", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPut, base+"/role", adminToken, map[string]string{"role": "superuser"})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "invalid_role", errorCode(t, raw))
		status, raw = doJSON(t, http.MethodPost, "/api/v1/users/not-a-uuid/deactivate", adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		status, raw = doJSON(t, http.MethodPost, "/api/v1/users/00000000-0000-0000-0000-00000000dead/deactivate", adminToken, nil)
		require.Equal(t, http.StatusNotFound, status, string(raw))
	})

	t.Run("a role change reaches an open session", func(t *testing.T) {
		promoted := request[adminUserRow](t, http.MethodPut, base+"/role", adminToken,
			map[string]string{"role": "admin"}, http.StatusOK)
		require.Equal(t, "admin", promoted.Role)

		// The old token belongs to the previous generation, so it stops working
		// and the person signs in again to get the new role.
		status, _ := doJSON(t, http.MethodGet, "/api/v1/me", userToken, nil)
		require.Equal(t, http.StatusUnauthorized, status)
		userToken = login(t, "e2e-viewer@example.com", adminPass)
		require.Equal(t, "admin", request[userProfile](t, http.MethodGet, "/api/v1/me", userToken, nil, http.StatusOK).Role)

		demoted := request[adminUserRow](t, http.MethodPut, base+"/role", adminToken,
			map[string]string{"role": "member"}, http.StatusOK)
		require.Equal(t, "member", demoted.Role)
		status, _ = doJSON(t, http.MethodGet, "/api/v1/users", userToken, nil)
		require.Equal(t, http.StatusUnauthorized, status, "the admin session ends when the role is taken away")
		userToken = login(t, "e2e-viewer@example.com", adminPass)
	})

	t.Run("deactivation locks the account out everywhere", func(t *testing.T) {
		session := request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": "e2e-viewer@example.com", "password": adminPass}, http.StatusOK)

		off := request[adminUserRow](t, http.MethodPost, base+"/deactivate", adminToken, nil, http.StatusOK)
		require.True(t, off.Disabled)
		require.NotNil(t, off.DisabledAt)

		status, _ := doJSON(t, http.MethodGet, "/api/v1/me", session.Token, nil)
		require.Equal(t, http.StatusUnauthorized, status, "an open session ends at its next request")

		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/refresh", "", map[string]string{"refresh_token": session.RefreshToken})
		require.GreaterOrEqual(t, status, 400, "the refresh token no longer yields a session: "+string(raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": "e2e-viewer@example.com", "password": adminPass})
		require.Equal(t, http.StatusUnauthorized, status, "the right password gets the same answer as a wrong one: "+string(raw))

		var listed []adminUserRow
		listed = request[[]adminUserRow](t, http.MethodGet, "/api/v1/users?email=e2e-viewer", adminToken, nil, http.StatusOK)
		var found bool
		for _, u := range listed {
			if u.ID == me.ID {
				found = true
				require.True(t, u.Disabled, "the account list shows who is deactivated")
			}
		}
		require.True(t, found, "a deactivated account stays in the list, with its history")
	})

	t.Run("reactivation restores the account", func(t *testing.T) {
		on := request[adminUserRow](t, http.MethodPost, base+"/reactivate", adminToken, nil, http.StatusOK)
		require.False(t, on.Disabled)
		require.Nil(t, on.DisabledAt)
		token := login(t, "e2e-viewer@example.com", adminPass)
		require.Equal(t, me.ID, request[userProfile](t, http.MethodGet, "/api/v1/me", token, nil, http.StatusOK).ID)
	})
}
