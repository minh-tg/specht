//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

type projectWithRole struct {
	Slug        string `json:"slug"`
	Role        string `json:"role"`
	Permissions *struct {
		RequestWaiver  bool `json:"request_waiver"`
		ManageWaivers  bool `json:"manage_waivers"`
		ApproveWaivers bool `json:"approve_waivers"`
		ManageMembers  bool `json:"manage_members"`
		ManageCI       bool `json:"manage_ci"`
		Triage         bool `json:"triage"`
		UploadReports  bool `json:"upload_reports"`
	} `json:"permissions"`
}

// TestE2E_ProjectRoleAndKeyManagement covers what the UI relies on to show
// the right controls: the project read carries the caller's effective role and
// permissions, and project managers, not only global admins, manage the
// project's API keys.
func TestE2E_ProjectRoleAndKeyManagement(t *testing.T) {
	slug := newProject(t, "perms")
	userToken := login(t, "e2e-viewer@example.com", adminPass)
	me := request[userProfile](t, http.MethodGet, "/api/v1/me", userToken, nil, http.StatusOK)
	setRole := func(role string) {
		t.Helper()
		status, raw := doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
			map[string]string{"user_id": me.ID, "role": role})
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, status, string(raw))
	}
	read := func(token string) projectWithRole {
		t.Helper()
		return request[projectWithRole](t, http.MethodGet, "/api/v1/projects/"+slug, token, nil, http.StatusOK)
	}

	t.Run("a global admin is admin everywhere", func(t *testing.T) {
		p := read(adminToken)
		require.Equal(t, "admin", p.Role)
		require.NotNil(t, p.Permissions)
		require.True(t, p.Permissions.ManageCI)
		require.True(t, p.Permissions.ApproveWaivers)
	})

	t.Run("a member can ask for waivers and nothing else", func(t *testing.T) {
		setRole("member")
		p := read(userToken)
		require.Equal(t, "member", p.Role)
		require.NotNil(t, p.Permissions)
		require.True(t, p.Permissions.RequestWaiver)
		require.False(t, p.Permissions.ManageCI)
		require.False(t, p.Permissions.ApproveWaivers)
		require.False(t, p.Permissions.Triage)
		require.False(t, p.Permissions.UploadReports)

		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/apikeys", userToken,
			map[string]string{"project": slug, "name": "ci"})
		require.Equal(t, http.StatusForbidden, status, string(raw))
		status, _ = doJSON(t, http.MethodGet, "/api/v1/auth/apikeys?project="+slug, userToken, nil)
		require.Equal(t, http.StatusForbidden, status)
	})

	t.Run("a manager sets up CI", func(t *testing.T) {
		setRole("manager")
		p := read(userToken)
		require.Equal(t, "manager", p.Role)
		require.NotNil(t, p.Permissions)
		require.True(t, p.Permissions.ManageCI)
		require.True(t, p.Permissions.ApproveWaivers)
		require.True(t, p.Permissions.Triage)
		require.True(t, p.Permissions.UploadReports)

		created := request[apiKeyResponse](t, http.MethodPost, "/api/v1/auth/apikeys", userToken,
			map[string]string{"project": slug, "name": "ci-by-manager"}, http.StatusCreated)
		require.NotEmpty(t, created.RawKey)

		keys := request[[]apiKeyResponse](t, http.MethodGet, "/api/v1/auth/apikeys?project="+slug, userToken, nil, http.StatusOK)
		require.NotEmpty(t, keys)

		status, raw := doJSON(t, http.MethodDelete, "/api/v1/auth/apikeys/"+created.ID+"?project="+slug, userToken, nil)
		require.Equal(t, http.StatusNoContent, status, string(raw))
	})

	t.Run("a manager of another project has no key rights here", func(t *testing.T) {
		other := newProject(t, "perms-other")
		status, raw := doJSON(t, http.MethodPost, "/api/v1/auth/apikeys", userToken,
			map[string]string{"project": other, "name": "ci"})
		require.Equal(t, http.StatusForbidden, status, string(raw))
	})
}
