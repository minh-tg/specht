//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// ssoSignIn runs one SSO login for email with the given IdP group membership
// and returns the access token and the account it signed in to.
func ssoSignIn(t *testing.T, email string, groups []string) (string, profileEnvelope) {
	t.Helper()
	fakes.idp.setEmail(email)
	fakes.idp.setGroups(groups)
	status, location, cookies := ssoExchange(t, "")
	token := ssoToken(t, status, location, cookies)
	me := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", token, nil, http.StatusOK)
	return token, me
}

// SSO_ADMIN_GROUPS is platform-team on the e2e server. The role an admin
// group granted follows the group: the IdP takes it back when the group is
// gone, and leaves alone an admin role an operator granted.
func TestE2E_SSOAdminGroupsWorkBothWays(t *testing.T) {
	t.Cleanup(func() {
		fakes.idp.setEmail(e2eSSOEmail)
		fakes.idp.setGroups(e2eSSOGroups)
	})

	t.Run("leaving the admin group ends the admin role and its sessions", func(t *testing.T) {
		email := "e2e-sso-demote@example.com"
		adminTok, me := ssoSignIn(t, email, e2eSSOGroups)
		require.Equal(t, "admin", me.Role, "the admin group provisions a global admin")

		_, me = ssoSignIn(t, email, []string{"developers"})
		require.NotEqual(t, "admin", me.Role, "without the group the next login is not an admin")

		status, _ := doJSON(t, http.MethodGet, "/api/v1/me", adminTok, nil)
		require.Equal(t, http.StatusUnauthorized, status, "the admin token from before the demotion stops working")

		_, me = ssoSignIn(t, email, e2eSSOGroups)
		require.Equal(t, "admin", me.Role, "rejoining the group grants the role again")
	})

	t.Run("an IdP with no groups claim demotes too", func(t *testing.T) {
		email := "e2e-sso-nogroups@example.com"
		_, me := ssoSignIn(t, email, e2eSSOGroups)
		require.Equal(t, "admin", me.Role)

		_, me = ssoSignIn(t, email, nil)
		require.NotEqual(t, "admin", me.Role)
	})

	t.Run("an admin role granted by hand stays after the group is gone", func(t *testing.T) {
		email := "e2e-sso-manual@example.com"
		_, me := ssoSignIn(t, email, e2eSSOGroups)
		require.Equal(t, "admin", me.Role)

		request[map[string]any](t, http.MethodPut, "/api/v1/users/"+me.ID+"/role", adminToken,
			map[string]string{"role": "admin"}, http.StatusOK)

		_, me = ssoSignIn(t, email, []string{"developers"})
		require.Equal(t, "admin", me.Role, "a grant an operator made is not the IdP's to take back")
	})
}
