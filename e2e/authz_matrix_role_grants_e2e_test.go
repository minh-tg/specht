//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/minh-tg/specht/internal/audit"
)

// Rows that send a role above member. The base rows of the matrix grant only
// `member`, which every caller who may grant at all can do, so they never reach
// the ceilings on the role handed out:
//
//   - the rank ceiling: a caller grants at most its own effective role;
//   - requireDirectGrantCeiling: manager or admin, by a member row, a team
//     link or an invite, needs a direct project row at or above the role. A
//     rank that comes only from a team link grants nothing above member;
//   - validateMemberRoleUpdate: a manager may not rewrite a peer or a
//     superior;
//   - requireDelegationCeiling: adding a person to a team hands them every
//     role the team is linked at, so a team admin needs a direct project row
//     at or above each elevated link.
//
// To reach the second ceiling the project rows raise the project's team link
// (TeamLinked, whose only member is C10) to admin for the length of the cell.
// C10 then holds admin through the team and no direct row, which is the caller
// the ceiling exists for. The link goes back to member when the cell ends.
//
// What is not here, and why:
//
//   - Invites with `role: admin`. The API refuses the role for every caller
//     (`400 invalid_invite_role`, "member or manager" in openapi.yaml) before
//     it looks at who asks, so there is no ceiling to reach.
//   - Team members with `role: manager`. openapi.yaml lists `manager` in the
//     MemberGrantRequest enum, but a team role is `admin` or `member` and the
//     server answers `400 invalid_member_role`. The docs and the code
//     disagree, so no row encodes either.

// personID is the account behind a caller that signs in with a working
// session, and empty for every other class.
func (f *authzFixtures) personID(c authzCaller) string {
	if !c.isLiveSession() {
		return ""
	}
	return f.callers[c].UserID
}

// azSetTeamLink points a project's link to a team at role.
func azSetTeamLink(t *testing.T, slug, teamID, role string) {
	t.Helper()
	request[map[string]any](t, http.MethodPost, "/api/v1/projects/"+slug+"/teams", adminToken,
		map[string]string{"team_id": teamID, "role": role}, http.StatusCreated)
}

// azUnlinkTeam removes a project's link to a team.
func azUnlinkTeam(t *testing.T, slug, teamID string) {
	t.Helper()
	status, raw := doJSON(t, http.MethodDelete, "/api/v1/projects/"+slug+"/teams/"+teamID, adminToken, nil)
	if status != http.StatusNoContent {
		t.Errorf("unlink team %s from %s: %d %s", teamID, slug, status, raw)
	}
}

// teamDerivedAdmin lifts the tenant's linked team to admin for one cell, so its
// member C10 holds admin with no direct row.
func teamDerivedAdmin(t *testing.T, _ *authzFixtures, a *authzAttempt) {
	azSetTeamLink(t, a.T.Slug, a.T.TeamLinked, "admin")
	t.Cleanup(func() { azSetTeamLink(t, a.T.Slug, a.T.TeamLinked, "member") })
}

// prepareAll runs the steps in order.
func prepareAll(steps ...func(*testing.T, *authzFixtures, *authzAttempt)) func(*testing.T, *authzFixtures, *authzAttempt) {
	return func(t *testing.T, f *authzFixtures, a *authzAttempt) {
		for _, step := range steps {
			step(t, f, a)
		}
	}
}

// existingMember makes the target a direct member at role before the call.
func existingMember(role string) func(*testing.T, *authzFixtures, *authzAttempt) {
	return func(t *testing.T, _ *authzFixtures, a *authzAttempt) {
		azAddMember(t, a.T.Slug, a.Obj["user"], role)
	}
}

// teamAdminOfLinkedTeam makes the caller, when it is a person, admin of a
// fresh team that the tenant links at role, and unlinks the team when the cell
// ends so the people added to it keep no access.
func teamAdminOfLinkedTeam(role string) func(*testing.T, *authzFixtures, *authzAttempt) {
	return func(t *testing.T, f *authzFixtures, a *authzAttempt) {
		a.Obj["team"] = azTeam(t, f)
		if uid := f.personID(a.Caller); uid != "" {
			azAddTeamMember(t, a.Obj["team"], uid, "admin")
		}
		azSetTeamLink(t, a.T.Slug, a.Obj["team"], role)
		t.Cleanup(func() { azUnlinkTeam(t, a.T.Slug, a.Obj["team"]) })
	}
}

// visibleFreshTeam makes a team the caller can see, so a link the caller may
// make is made and answers 201, not the 404 of a team it cannot see.
func visibleFreshTeam(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["team"] = azTeam(t, f)
	if uid := f.personID(a.Caller); uid != "" {
		azAddTeamMember(t, a.Obj["team"], uid, "member")
	}
	// The link exists only when the call was allowed; a 404 here is fine.
	t.Cleanup(func() {
		_, _ = doJSON(t, http.MethodDelete, "/api/v1/projects/"+a.T.Slug+"/teams/"+a.Obj["team"], adminToken, nil)
	})
}

func grantBody(role string) func(*authzFixtures, *authzAttempt) any {
	return func(_ *authzFixtures, a *authzAttempt) any {
		return map[string]string{"user_id": a.Obj["user"], "role": role}
	}
}

// roleGrantRows returns the rows that send manager or admin.
func roleGrantRows() []authzRow {
	managersOnly := allowOnly(managers...)
	adminsOnly := allowOnly(projectAdmins...)
	// A manager may not touch a peer or a superior; admins may.
	peerSafe := with(managersOnly, outcomeDeny403, callerManager)

	membersPath := inProject("/members")
	freshTarget := freshUser("user")

	return []authzRow{
		// Project members, a fresh person each time. A manager grants manager
		// and not admin; an admin grants both; C10 holds admin through the team
		// link and still grants neither.
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/members", Variant: "role-manager",
			Path: membersPath, Prepare: prepareAll(freshTarget, teamDerivedAdmin), Body: grantBody("manager"),
			Want: managersOnly, Audit: audit.EventAddProjectMember,
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/members", Variant: "role-admin",
			Path: membersPath, Prepare: prepareAll(freshTarget, teamDerivedAdmin), Body: grantBody("admin"),
			Want: adminsOnly, Audit: audit.EventAddProjectMember,
		},
		// Peer protection: the target already holds a role. A manager promotes a
		// member, and cannot rewrite a manager or an admin.
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/members", Variant: "member-to-manager",
			Path: membersPath, Prepare: prepareAll(freshTarget, existingMember("member")), Body: grantBody("manager"),
			Want: managersOnly, Audit: audit.EventAddProjectMember,
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/members", Variant: "manager-to-member",
			Path: membersPath, Prepare: prepareAll(freshTarget, existingMember("manager")), Body: grantBody("member"),
			Want: peerSafe, Audit: audit.EventAddProjectMember,
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/members", Variant: "admin-to-member",
			Path: membersPath, Prepare: prepareAll(freshTarget, existingMember("admin")), Body: grantBody("member"),
			Want: peerSafe, Audit: audit.EventAddProjectMember,
		},

		// Invites. Only member and manager are invitable roles.
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/invites", Variant: "role-manager",
			Path: inProject("/invites"), Prepare: teamDerivedAdmin, Body: jsonBody(map[string]string{"role": "manager"}),
			Want: managersOnly, Audit: audit.EventCreateInvite,
		},

		// Team links. The team is one the caller can see, so a link the caller
		// may make is made.
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/teams", Variant: "role-manager",
			Path: inProject("/teams"), Prepare: prepareAll(visibleFreshTeam, teamDerivedAdmin),
			Body: func(_ *authzFixtures, a *authzAttempt) any {
				return map[string]string{"team_id": a.Obj["team"], "role": "manager"}
			},
			Want: managersOnly, Audit: audit.EventLinkProjectTeam,
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/teams", Variant: "role-admin",
			Path: inProject("/teams"), Prepare: prepareAll(visibleFreshTeam, teamDerivedAdmin),
			Body: func(_ *authzFixtures, a *authzAttempt) any {
				return map[string]string{"team_id": a.Obj["team"], "role": "admin"}
			},
			Want: adminsOnly, Audit: audit.EventLinkProjectTeam,
		},

		// Team members. `admin` is a team role, held on a team linked to no
		// project, so the callers who may add `member` may add it too.
		{
			Method: "POST", Pattern: "/api/v1/teams/{id}/members", Variant: "role-admin",
			Path:    func(_ *authzFixtures, a *authzAttempt) string { return "/api/v1/teams/" + a.T.TeamOwned + "/members" },
			Prepare: freshTarget, Body: grantBody("admin"),
			Want: with(allowOnly(callerTeamAdmin, callerInstanceAdmin), outcomeDeny404,
				callerNoProject, callerMember, callerManager, callerProjectAdmin, callerTeamMember),
			Foreign: with(allowOnly(callerInstanceAdmin), outcomeDeny404,
				callerNoProject, callerMember, callerManager, callerProjectAdmin, callerTeamMember, callerTeamAdmin),
			Audit: audit.EventAddTeamMember,
		},
		// Delegation ceiling: the caller administers a team that the project
		// links at manager or admin, and holds no such row directly.
		{
			Method: "POST", Pattern: "/api/v1/teams/{id}/members", Variant: "team-linked-manager",
			Path:    func(_ *authzFixtures, a *authzAttempt) string { return "/api/v1/teams/" + a.Obj["team"] + "/members" },
			Prepare: prepareAll(freshTarget, teamAdminOfLinkedTeam("manager")), Body: grantBody("member"),
			Want: managersOnly, Audit: audit.EventAddTeamMember,
		},
		{
			Method: "POST", Pattern: "/api/v1/teams/{id}/members", Variant: "team-linked-admin",
			Path:    func(_ *authzFixtures, a *authzAttempt) string { return "/api/v1/teams/" + a.Obj["team"] + "/members" },
			Prepare: prepareAll(freshTarget, teamAdminOfLinkedTeam("admin")), Body: grantBody("member"),
			Want: adminsOnly, Audit: audit.EventAddTeamMember,
		},
	}
}
