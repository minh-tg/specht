//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// Membership integrity: the rules below the route level that keep a project
// governable (an admin who can sign in), keep team delegation inside its
// ceiling, and keep the existence of projects and teams private.

type miPerson struct {
	ID    string
	Email string
	Token string
}

func miNewPerson(t *testing.T, label string) miPerson {
	t.Helper()
	a := registerPerson(t, "mi-"+label)
	return miPerson{ID: a.UserID, Email: a.Email, Token: a.Token}
}

type miProjectView struct {
	Role string `json:"role"`
}

// miRole returns the caller's effective role on the project as GET
// /projects/{slug} reports it, or "" when the caller is refused.
func miRole(t *testing.T, slug, token string) string {
	t.Helper()
	status, raw := doJSON(t, http.MethodGet, "/api/v1/projects/"+slug, token, nil)
	if status != http.StatusOK {
		return ""
	}
	var v miProjectView
	require.NoError(t, json.Unmarshal(raw, &v))
	return v.Role
}

func miTeam(t *testing.T, label string) string {
	t.Helper()
	return request[teamResponse](t, http.MethodPost, "/api/v1/teams", adminToken,
		map[string]string{"name": "mi-" + label + "-" + randomHex(4)}, http.StatusCreated).ID
}

func miTeamAdd(t *testing.T, token, teamID, userID, role string) int {
	t.Helper()
	status, _ := doJSON(t, http.MethodPost, "/api/v1/teams/"+teamID+"/members", token,
		map[string]string{"user_id": userID, "role": role})
	return status
}

func miLink(t *testing.T, token, slug, teamID, role string) int {
	t.Helper()
	status, _ := doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/teams", token,
		map[string]string{"team_id": teamID, "role": role})
	return status
}

func miAddMember(t *testing.T, token, slug, userID, role string) (int, string) {
	t.Helper()
	status, raw := doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", token,
		map[string]string{"user_id": userID, "role": role})
	code := ""
	if status >= 400 {
		code = errorCode(t, raw)
	}
	return status, code
}

func miRemoveMember(t *testing.T, token, slug, userID string) (int, string) {
	t.Helper()
	status, raw := doJSON(t, http.MethodDelete, "/api/v1/projects/"+slug+"/members/"+userID, token, nil)
	code := ""
	if status >= 400 {
		code = errorCode(t, raw)
	}
	return status, code
}

// miDirectRole returns the user's direct project_members role, or "" when the
// user has no direct row.
func miDirectRole(t *testing.T, slug, userID string) string {
	t.Helper()
	members := request[[]memberResponse](t, http.MethodGet, "/api/v1/projects/"+slug+"/members", adminToken, nil, http.StatusOK)
	for _, m := range members {
		if m.UserID == userID {
			return m.Role
		}
	}
	return ""
}

// A deactivated account cannot sign in, so it does not count as a project
// admin: the last admin who can sign in may not leave, and deactivating the
// only active admin of a project is refused unless the caller confirms.
func TestMembershipIntegrity_DeactivatedAdminDoesNotCount(t *testing.T) {
	slug := newProject(t, "mi-orphan")
	me := request[userProfile](t, http.MethodGet, "/api/v1/me", adminToken, nil, http.StatusOK)
	a := miNewPerson(t, "orphan-a")
	d := miNewPerson(t, "orphan-d")
	for _, id := range []string{a.ID, d.ID} {
		status, _ := miAddMember(t, adminToken, slug, id, "admin")
		require.Equal(t, http.StatusCreated, status)
	}
	status, _ := miRemoveMember(t, adminToken, slug, me.ID)
	require.Equal(t, http.StatusNoContent, status)

	// d is not the only admin, so deactivating it needs no confirmation.
	status, raw := doJSON(t, http.MethodPost, "/api/v1/users/"+d.ID+"/deactivate", adminToken, nil)
	require.Equalf(t, http.StatusOK, status, "%s", raw)

	// a is now the only admin who can sign in and cannot leave or step down.
	status, code := miRemoveMember(t, a.Token, slug, a.ID)
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "last_admin", code)
	status, code = miAddMember(t, a.Token, slug, a.ID, "manager")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "last_admin", code)
	require.Equal(t, "admin", miDirectRole(t, slug, a.ID))

	// Deactivating a is refused and names the project.
	status, raw = doJSON(t, http.MethodPost, "/api/v1/users/"+a.ID+"/deactivate", adminToken, nil)
	require.Equalf(t, http.StatusConflict, status, "%s", raw)
	require.Equal(t, "sole_project_admin", errorCode(t, raw))
	require.Contains(t, string(raw), slug)
	profile := request[userProfile](t, http.MethodGet, "/api/v1/me", a.Token, nil, http.StatusOK)
	require.Equal(t, a.ID, profile.ID, "the refused deactivation left the account active")

	// A false confirmation changes nothing; an explicit one goes through.
	status, _ = doJSON(t, http.MethodPost, "/api/v1/users/"+a.ID+"/deactivate", adminToken, map[string]bool{"force": false})
	require.Equal(t, http.StatusConflict, status)
	status, raw = doJSON(t, http.MethodPost, "/api/v1/users/"+a.ID+"/deactivate", adminToken, map[string]bool{"force": true})
	require.Equalf(t, http.StatusOK, status, "%s", raw)
}
