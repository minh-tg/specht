//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"sync"
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

// A manager's write on a person runs while an admin promotes that person. The
// peer rule (a manager may not touch an admin) is judged on the role the person
// holds when the write lands, so the manager never undoes the promotion.
func TestMembershipIntegrity_ManagerCannotOverwriteAConcurrentPromotion(t *testing.T) {
	slug := newProject(t, "mi-peer")
	mgr := miNewPerson(t, "peer-mgr")
	target := miNewPerson(t, "peer-t")
	status, _ := miAddMember(t, adminToken, slug, mgr.ID, "manager")
	require.Equal(t, http.StatusCreated, status)

	const rounds = 100
	demoted, removed := 0, 0
	for i := 0; i < rounds; i++ {
		// Reset: the global admin (still a direct admin) sets the target to member.
		status, _ := miAddMember(t, adminToken, slug, target.ID, "member")
		require.Equal(t, http.StatusCreated, status)

		remove := i%2 == 1
		var wg sync.WaitGroup
		start := make(chan struct{})
		var adminStatus, mgrStatus int
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			adminStatus, _ = miAddMember(t, adminToken, slug, target.ID, "admin")
		}()
		go func() {
			defer wg.Done()
			<-start
			if remove {
				mgrStatus, _ = miRemoveMember(t, mgr.Token, slug, target.ID)
			} else {
				mgrStatus, _ = miAddMember(t, mgr.Token, slug, target.ID, "manager")
			}
		}()
		close(start)
		wg.Wait()
		require.Equal(t, http.StatusCreated, adminStatus, "the promotion itself always lands")
		// The manager's write may win before the promotion (then the admin
		// promotes the result) or lose to it (then it is refused), never both.
		final := miDirectRole(t, slug, target.ID)
		require.Equal(t, "admin", final, "round %d: the promotion must be the last word (manager status %d)", i, mgrStatus)
		if mgrStatus < 300 && final != "admin" {
			if remove {
				removed++
			} else {
				demoted++
			}
		}
	}
	require.Zero(t, demoted+removed, "the manager overwrote a fresh admin")
}

// A project the caller cannot see and a project that does not exist answer
// alike on every project route, with the same status and body, so a signed-in
// account or a foreign key cannot learn which slugs exist.
func TestMembershipIntegrity_MissingAndForeignProjectsAnswerAlike(t *testing.T) {
	existing := newProject(t, "mi-oracle")
	missing := "mi-none-" + randomHex(6)
	outsider := miNewPerson(t, "oracle")
	foreignKey := mintKey(t, newProject(t, "mi-oracle-key"))
	zero := "00000000-0000-4000-8000-000000000000"

	routes := []struct {
		method, suffix string
		body           any
	}{
		{http.MethodPut, "", map[string]string{"description": "x"}},
		{http.MethodDelete, "", nil},
		{http.MethodGet, "/teams", nil},
		{http.MethodPost, "/teams", map[string]string{"team_id": zero, "role": "member"}},
		{http.MethodDelete, "/teams/" + zero, nil},
		{http.MethodPut, "/policy", map[string]string{"template_name": ""}},
		{http.MethodPut, "/policy/overrides", map[string]any{"overrides": map[string]string{}}},
		// Routes that already checked access first stay alike.
		{http.MethodGet, "", nil},
		{http.MethodGet, "/members", nil},
		{http.MethodPost, "/members", map[string]string{"user_id": outsider.ID, "role": "member"}},
	}
	for _, who := range []struct{ name, token string }{{"session without access", outsider.Token}, {"foreign project key", foreignKey}} {
		for _, rt := range routes {
			sExist, bExist := doJSON(t, rt.method, "/api/v1/projects/"+existing+rt.suffix, who.token, rt.body)
			sMissing, bMissing := doJSON(t, rt.method, "/api/v1/projects/"+missing+rt.suffix, who.token, rt.body)
			require.Equalf(t, sExist, sMissing, "%s %s%s: status differs (existing %s, missing %s)", who.name, rt.method, rt.suffix, bExist, bMissing)
			require.Equalf(t, string(bExist), string(bMissing), "%s %s%s: body differs", who.name, rt.method, rt.suffix)
			require.Containsf(t, []int{http.StatusForbidden, http.StatusUnauthorized}, sMissing, "%s %s%s: want a refusal, got %d %s", who.name, rt.method, rt.suffix, sMissing, bMissing)
		}
	}
}

func miTeamIDs(t *testing.T, token string) map[string]bool {
	t.Helper()
	ids := map[string]bool{}
	for _, tm := range request[[]teamResponse](t, http.MethodGet, "/api/v1/teams", token, nil, http.StatusOK) {
		ids[tm.ID] = true
	}
	return ids
}

// The team directory shows a person the teams linked to a project they can
// reach and the teams they belong to, and nothing else. A team they cannot see
// answers like a team that does not exist, so ids cannot be probed.
func TestMembershipIntegrity_TeamDirectoryStaysInsideTheCallersProjects(t *testing.T) {
	x := newProject(t, "mi-dirx")
	y := newProject(t, "mi-diry")
	memberX := miNewPerson(t, "dir-x")
	status, _ := miAddMember(t, adminToken, x, memberX.ID, "member")
	require.Equal(t, http.StatusCreated, status)
	stranger := miNewPerson(t, "dir-c5")
	yOnly := miNewPerson(t, "dir-y")
	viaTeam := miNewPerson(t, "dir-viateam")
	belongs := miNewPerson(t, "dir-belongs")

	tx := miTeam(t, "dir-x")       // linked to X
	ty := miTeam(t, "dir-y")       // linked to Y only
	tfree := miTeam(t, "dir-free") // linked nowhere
	tlinkedX := miTeam(t, "dir-viateam")
	require.Equal(t, http.StatusCreated, miLink(t, adminToken, x, tx, "member"))
	require.Equal(t, http.StatusCreated, miLink(t, adminToken, y, ty, "admin"))
	require.Equal(t, http.StatusCreated, miTeamAdd(t, adminToken, ty, yOnly.ID, "member"))
	require.Equal(t, http.StatusCreated, miTeamAdd(t, adminToken, tx, memberX.ID, "member"))
	require.Equal(t, http.StatusCreated, miLink(t, adminToken, x, tlinkedX, "member"))
	require.Equal(t, http.StatusCreated, miTeamAdd(t, adminToken, tlinkedX, viaTeam.ID, "member"))
	require.Equal(t, http.StatusCreated, miTeamAdd(t, adminToken, tfree, belongs.ID, "member"))

	// A member of X: the teams linked to X, not the team that administers Y,
	// not a team linked nowhere.
	ids := miTeamIDs(t, memberX.Token)
	require.True(t, ids[tx], "a team linked to the caller's project")
	require.True(t, ids[tlinkedX])
	require.False(t, ids[ty], "a team linked only to a project the caller cannot reach")
	require.False(t, ids[tfree])

	// Access through a team counts the same as a direct row.
	ids = miTeamIDs(t, viaTeam.Token)
	require.True(t, ids[tx] && ids[tlinkedX])
	require.False(t, ids[ty])

	// A team the caller belongs to is visible even when it is linked nowhere.
	ids = miTeamIDs(t, belongs.Token)
	require.True(t, ids[tfree])
	require.False(t, ids[tx] || ids[ty])

	require.Empty(t, miTeamIDs(t, stranger.Token), "an account with no project and no team sees no team")
	all := miTeamIDs(t, adminToken)
	require.True(t, all[tx] && all[ty] && all[tfree], "a global admin still sees every team")

	// Rosters follow the same rule, and an invisible team answers exactly like
	// a team that does not exist.
	missing := "00000000-0000-4000-8000-000000000000"
	for _, who := range []miPerson{memberX, stranger, belongs} {
		sMissing, bMissing := doJSON(t, http.MethodGet, "/api/v1/teams/"+missing+"/members", who.Token, nil)
		require.Equal(t, http.StatusNotFound, sMissing)
		sInvisible, bInvisible := doJSON(t, http.MethodGet, "/api/v1/teams/"+ty+"/members", who.Token, nil)
		require.Equal(t, sMissing, sInvisible, "status of a team the caller cannot see")
		require.Equal(t, string(bMissing), string(bInvisible), "body of a team the caller cannot see")
	}
	roster := request[[]teamMemberResponse](t, http.MethodGet, "/api/v1/teams/"+tx+"/members", memberX.Token, nil, http.StatusOK)
	require.Len(t, roster, 2, "the creating admin and memberX")
	request[[]teamMemberResponse](t, http.MethodGet, "/api/v1/teams/"+tfree+"/members", belongs.Token, nil, http.StatusOK)
	request[[]teamMemberResponse](t, http.MethodGet, "/api/v1/teams/"+ty+"/members", adminToken, nil, http.StatusOK)

	// Writes to a roster do not tell a missing team from one the caller cannot
	// see either.
	sMissing, bMissing := doJSON(t, http.MethodPost, "/api/v1/teams/"+missing+"/members", memberX.Token,
		map[string]string{"user_id": stranger.ID, "role": "member"})
	sInvisible, bInvisible := doJSON(t, http.MethodPost, "/api/v1/teams/"+ty+"/members", memberX.Token,
		map[string]string{"user_id": stranger.ID, "role": "member"})
	require.Equal(t, sMissing, sInvisible)
	require.Equal(t, string(bMissing), string(bInvisible))
}
