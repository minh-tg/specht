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

// A caller whose rank on a project comes only from a team link cannot write
// direct rows at manager level or above, so a team admin cannot turn a link
// into a lasting grant or reach past the delegation ceiling on the team roster.
func TestMembershipIntegrity_TeamOnlyCallerCannotWriteElevatedRows(t *testing.T) {
	x := newProject(t, "mi-byp")
	ta := miNewPerson(t, "byp-ta")
	outsider := miNewPerson(t, "byp-out")
	other := miNewPerson(t, "byp-other")
	tm := miTeam(t, "byp")
	otherTeam := miTeam(t, "byp-other")
	require.Equal(t, http.StatusCreated, miTeamAdd(t, adminToken, tm, ta.ID, "admin"))
	require.Equal(t, http.StatusCreated, miLink(t, adminToken, x, tm, "admin"))
	require.Equal(t, "admin", miRole(t, x, ta.Token))
	require.Equal(t, "", miDirectRole(t, x, ta.ID))
	require.Equal(t, http.StatusForbidden, miTeamAdd(t, ta.Token, tm, outsider.ID, "member"), "the team roster ceiling holds")

	// The two-request bypass: writing a direct admin or manager row for self.
	for _, role := range []string{"admin", "manager"} {
		status, code := miAddMember(t, ta.Token, x, ta.ID, role)
		require.Equalf(t, http.StatusForbidden, status, "self as %s (code %s)", role, code)
		status, code = miAddMember(t, ta.Token, x, other.ID, role)
		require.Equalf(t, http.StatusForbidden, status, "another person as %s (code %s)", role, code)
	}
	require.Equal(t, "", miDirectRole(t, x, ta.ID))
	require.Equal(t, http.StatusForbidden, miTeamAdd(t, ta.Token, tm, outsider.ID, "member"), "still refused")
	require.Equal(t, "", miRole(t, x, outsider.Token))

	// Linking another team at manager or above is the same write by other means.
	require.Equal(t, http.StatusForbidden, miLink(t, ta.Token, x, otherTeam, "manager"))
	require.Equal(t, http.StatusForbidden, miLink(t, ta.Token, x, otherTeam, "admin"))
	// So is an invite at manager.
	status, _ := doJSON(t, http.MethodPost, "/api/v1/projects/"+x+"/invites", ta.Token, map[string]any{"role": "manager"})
	require.Equal(t, http.StatusForbidden, status)

	// Member-level writes stay open to the effective role.
	status, code := miAddMember(t, ta.Token, x, other.ID, "member")
	require.Equalf(t, http.StatusCreated, status, "code %s", code)
	require.Equal(t, http.StatusCreated, miLink(t, ta.Token, x, otherTeam, "member"))
	status, _ = doJSON(t, http.MethodPost, "/api/v1/projects/"+x+"/invites", ta.Token, map[string]any{"role": "member"})
	require.Equal(t, http.StatusCreated, status)
}

// A direct manager or admin keeps the rules they had: the direct row is the
// ceiling, whatever the team links add on top.
func TestMembershipIntegrity_DirectRoleStillDelegates(t *testing.T) {
	x := newProject(t, "mi-direct")
	mgr := miNewPerson(t, "direct-mgr")
	adm := miNewPerson(t, "direct-adm")
	a := miNewPerson(t, "direct-a")
	b := miNewPerson(t, "direct-b")
	for _, g := range []struct{ id, role string }{{mgr.ID, "manager"}, {adm.ID, "admin"}} {
		status, _ := miAddMember(t, adminToken, x, g.id, g.role)
		require.Equal(t, http.StatusCreated, status)
	}
	// A team link at admin lifts the manager's effective role, not the ceiling.
	tm := miTeam(t, "direct")
	require.Equal(t, http.StatusCreated, miTeamAdd(t, adminToken, tm, mgr.ID, "member"))
	require.Equal(t, http.StatusCreated, miLink(t, adminToken, x, tm, "admin"))
	require.Equal(t, "admin", miRole(t, x, mgr.Token))

	status, _ := miAddMember(t, mgr.Token, x, a.ID, "manager")
	require.Equal(t, http.StatusCreated, status, "a direct manager adds a manager")
	status, _ = miAddMember(t, mgr.Token, x, b.ID, "admin")
	require.Equal(t, http.StatusForbidden, status, "the link does not lift a direct manager to admin writes")

	status, _ = miAddMember(t, adm.Token, x, b.ID, "admin")
	require.Equal(t, http.StatusCreated, status, "a direct admin adds an admin")
	status, _ = doJSON(t, http.MethodPost, "/api/v1/projects/"+x+"/invites", adm.Token, map[string]any{"role": "manager"})
	require.Equal(t, http.StatusCreated, status)
	other := miTeam(t, "direct-other")
	require.Equal(t, http.StatusCreated, miLink(t, adm.Token, x, other, "manager"))
}

// Unlinking a team or removing a person from it ends the access it conferred,
// and nothing along the way leaves a direct row behind.
func TestMembershipIntegrity_UnlinkEndsTeamAccessWithoutALeftover(t *testing.T) {
	x := newProject(t, "mi-unlink")
	ta := miNewPerson(t, "unlink-ta")
	tm := miTeam(t, "unlink")
	require.Equal(t, http.StatusCreated, miTeamAdd(t, adminToken, tm, ta.ID, "admin"))
	require.Equal(t, http.StatusCreated, miLink(t, adminToken, x, tm, "admin"))

	status, _ := miAddMember(t, ta.Token, x, ta.ID, "admin")
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "", miDirectRole(t, x, ta.ID))

	status, _ = doJSON(t, http.MethodDelete, "/api/v1/projects/"+x+"/teams/"+tm, adminToken, nil)
	require.Equal(t, http.StatusNoContent, status)
	require.Equal(t, "", miRole(t, x, ta.Token), "unlinking ends access")
	require.Equal(t, "", miDirectRole(t, x, ta.ID))

	require.Equal(t, http.StatusCreated, miLink(t, adminToken, x, tm, "manager"))
	require.Equal(t, "manager", miRole(t, x, ta.Token))
	status, _ = doJSON(t, http.MethodDelete, "/api/v1/teams/"+tm+"/members/"+ta.ID, adminToken, nil)
	require.Equal(t, http.StatusNoContent, status)
	require.Equal(t, "", miRole(t, x, ta.Token), "leaving the team ends access")
	require.Equal(t, "", miDirectRole(t, x, ta.ID))
}
