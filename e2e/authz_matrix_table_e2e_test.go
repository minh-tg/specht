//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/minh-tg/specht/internal/audit"
)

// The expectation table of the authorization matrix. Every outcome is the
// intended policy, read from openapi.yaml (x-auth, x-required-role,
// x-required-scope and the descriptions), the guards in
// internal/usecase/access.go, members.go, teams.go and permissions.go, and
// deploy/README.md. The coordinator settled the unclear cells (U1 to U13 in
// the K0 report) before they were encoded:
//
//   - a key whose creator was removed from the project or deactivated is a
//     dead credential (Deny401), like a revoked or expired key;
//   - the admin scope implies read;
//   - project-admin settings, approvals, waiver requests, invites, members,
//     team links and member suggestions need a session, so every key is
//     refused there even with the admin scope;
//   - a foreign object addressed by id answers 403; an X slug paired with a
//     Y id in the path answers 404 for a caller who passes X's guard; a
//     foreign id in a query or body answers 403.

func api(path string) func(*authzFixtures, *authzAttempt) string {
	return func(*authzFixtures, *authzAttempt) string { return "/api/v1" + path }
}

func inProject(suffix string) func(*authzFixtures, *authzAttempt) string {
	return func(_ *authzFixtures, a *authzAttempt) string { return "/api/v1/projects/" + a.T.Slug + suffix }
}

func onFinding(suffix string) func(*authzFixtures, *authzAttempt) string {
	return func(_ *authzFixtures, a *authzAttempt) string { return "/api/v1/findings/" + a.T.FindingID + suffix }
}

func onObj(prefix, key, suffix string) func(*authzFixtures, *authzAttempt) string {
	return func(_ *authzFixtures, a *authzAttempt) string { return prefix + a.Obj[key] + suffix }
}

func projectObj(middle, key, suffix string) func(*authzFixtures, *authzAttempt) string {
	return func(_ *authzFixtures, a *authzAttempt) string {
		return "/api/v1/projects/" + a.T.Slug + middle + a.Obj[key] + suffix
	}
}

// xSlugObj pairs tenant X's slug with an object prepared in tenant Y.
func xSlugObj(middle, key, suffix string) func(*authzFixtures, *authzAttempt) string {
	return func(f *authzFixtures, a *authzAttempt) string {
		return "/api/v1/projects/" + f.X.Slug + middle + a.Obj[key] + suffix
	}
}

func jsonBody(v any) func(*authzFixtures, *authzAttempt) any {
	return func(*authzFixtures, *authzAttempt) any { return v }
}

// Prepare helpers: each puts a fresh object into a.Obj under the given key.

func freshUser(key string) func(*testing.T, *authzFixtures, *authzAttempt) {
	return func(t *testing.T, _ *authzFixtures, a *authzAttempt) { a.Obj[key] = azRegister(t, "target").UserID }
}

func freshWaiver(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["waiver"] = createWaiver(t, a.T.Slug, f.unique("waiver"), a.T.FindingID, "").ID
}

func freshYWaiver(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["waiver"] = createWaiver(t, f.Y.Slug, f.unique("waiver"), f.Y.FindingID, "").ID
}

func revokedWaiver(t *testing.T, f *authzFixtures, a *authzAttempt) {
	freshWaiver(t, f, a)
	request[waiverDetail](t, http.MethodPost, "/api/v1/projects/"+a.T.Slug+"/waivers/"+a.Obj["waiver"]+"/revoke",
		adminToken, map[string]any{}, http.StatusOK)
}

func pendingWaiver(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["waiver"] = f.pendingRequest(t, a.T)
}

func pendingYWaiver(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["waiver"] = f.pendingRequest(t, f.Y)
}

func freshTemplate(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["template"] = request[struct {
		ID string `json:"id"`
	}](t, http.MethodPost, "/api/v1/policy-templates", adminToken, map[string]any{
		"name": f.unique("template"), "definition": map[string]string{"severity_floor": "high"},
	}, http.StatusCreated).ID
}

func freshKey(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["key"] = azScopedKey(t, f, a.T.Slug, `["ingest","read"]`).KeyID
}

func freshYKey(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["key"] = azScopedKey(t, f, f.Y.Slug, `["ingest","read"]`).KeyID
}

func freshEvidence(t *testing.T, _ *authzFixtures, a *authzAttempt) {
	a.Obj["evidence"] = azEvidence(t, a.T.FindingID)
}

func freshYEvidence(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["evidence"] = azEvidence(t, f.Y.FindingID)
}

func freshReport(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["report"] = f.azFreshReport(t, a.T)
}

func freshYReport(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["report"] = f.azFreshReport(t, f.Y)
}

func freshInvite(t *testing.T, _ *authzFixtures, a *authzAttempt) {
	a.Obj["invite"] = azInviteID(t, a.T.Slug)
}

func freshYInvite(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["invite"] = azInviteID(t, f.Y.Slug)
}

// freshZInvite mints a single-use token on the scratch project, so redeeming
// it changes no caller's standing in X or Y.
func freshZInvite(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["token"] = azInvite(t, f.ZSlug)
}

func freshMember(t *testing.T, _ *authzFixtures, a *authzAttempt) {
	p := azRegister(t, "member-target")
	azAddMember(t, a.T.Slug, p.UserID, "member")
	a.Obj["user"] = p.UserID
}

func freshTeamMember(teamOf func(*authzTenant) string) func(*testing.T, *authzFixtures, *authzAttempt) {
	return func(t *testing.T, _ *authzFixtures, a *authzAttempt) {
		p := azRegister(t, "team-target")
		a.Obj["team"] = teamOf(a.T)
		azAddTeamMember(t, a.Obj["team"], p.UserID, "member")
		a.Obj["user"] = p.UserID
	}
}

func freshLinkedTeam(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["team"] = azTeam(t, f)
	azLinkTeam(t, a.T.Slug, a.Obj["team"])
}

// freshProject makes a throwaway project for DELETE /projects/{slug}. In X
// the caller gets the standing it has in tenant X; in Y it gets none.
func freshProject(t *testing.T, f *authzFixtures, a *authzAttempt) {
	slug := newProject(t, "authz-del")
	azWatcherOff(t, slug)
	a.Obj["slug"] = slug
	if a.Tenant == authzTenantX {
		a.Token = f.grantHome(t, a.Caller, slug)
	}
}

func triagePrepare(t *testing.T, f *authzFixtures, a *authzAttempt) {
	a.Obj["state"] = f.otherAnalysisState(t, a.T.FindingID)
}

// undoPrepare records a triage change by the suite admin, so the attempt has
// a newest analysis event to undo.
func undoPrepare(t *testing.T, f *authzFixtures, a *authzAttempt) {
	request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+a.T.FindingID, adminToken,
		map[string]string{"analysis_state": f.otherAnalysisState(t, a.T.FindingID), "reason": "authz undo fixture"}, http.StatusOK)
	a.Obj["event"] = f.latestAnalysisEvent(t, a.T.FindingID)
}

func ssoCallbackPrepare(t *testing.T, _ *authzFixtures, a *authzAttempt) {
	authorize, cookies, _ := ssoLoginLeg(t, "")
	resp, err := noRedirectClient().Get(authorize)
	require.NoError(t, err)
	_ = resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	back, err := url.Parse(resp.Header.Get("Location"))
	require.NoError(t, err)
	a.Obj["callback"] = back.RequestURI()
	a.Cookies = cookies
}

func ssoCodePrepare(t *testing.T, _ *authzFixtures, a *authzAttempt) {
	status, location, cookies := ssoExchange(t, "")
	require.Equal(t, http.StatusFound, status)
	parsed, err := url.Parse(location)
	require.NoError(t, err)
	code, err := url.PathUnescape(strings.TrimPrefix(parsed.Fragment, "sso_code="))
	require.NoError(t, err)
	a.Obj["code"] = code
	// The exchange only accepts the code from the browser that started the login.
	a.Cookies = cookies
}

func requestBody(_ *authzFixtures, a *authzAttempt) any {
	return map[string]any{
		"target_ids": []string{a.T.FindingID},
		"reason":     "authz matrix request",
		"expires_at": time.Now().Add(30 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}
}

// authzRows is the table: one row per registered route, plus variants that
// pair one tenant's path with another tenant's id.
func authzRows() []authzRow {
	readers := allowOnly(projectReaders...)
	writers := allowOnly(projectWriters...)
	sessionManagers := allowOnly(managers...)
	sessionAdmins := allowOnly(projectAdmins...)
	signedIn := allowOnly(sessions...)
	instanceAdmin := allowOnly(callerInstanceAdmin)
	// teamRosterWriters is the policy for changing the roster of TeamOwned,
	// which is linked to no project: its admin and instance admins may; every
	// other session cannot see the team and gets the answer for a missing one.
	teamRosterWriters := with(allowOnly(callerTeamAdmin, callerInstanceAdmin), outcomeDeny404,
		callerNoProject, callerMember, callerManager, callerProjectAdmin, callerTeamMember)
	teamRosterWritersForeign := with(instanceAdmin, outcomeDeny404,
		callerNoProject, callerMember, callerManager, callerProjectAdmin, callerTeamMember, callerTeamAdmin)
	// mixedPair is the policy for an X slug carrying a Y id in the path: a
	// caller who passes X's guard learns only that the object is not in X.
	mixedPair := func(base map[authzCaller]authzOutcome, passers ...authzCaller) map[authzCaller]authzOutcome {
		return with(base, outcomeDeny404, passers...)
	}

	return []authzRow{
		// Meta and sign-in routes are public: the bearer is never read, so
		// every caller class gets the same answer.
		{Method: "GET", Pattern: "/api/v1/health", Path: api("/health"), Want: everyone(), Tenants: onlyX},
		{Method: "GET", Pattern: "/api/v1/ready", Path: api("/ready"), Want: everyone(), Tenants: onlyX},
		{Method: "GET", Pattern: "/api/v1/version", Path: api("/version"), Want: everyone(), Tenants: onlyX},
		{Method: "GET", Pattern: "/api/v1/capabilities", Path: api("/capabilities"), Want: everyone(), Tenants: onlyX},
		{
			Method: "GET", Pattern: "/api/v1/auth/sso/login", Path: api("/auth/sso/login"),
			Want: everyone(), Tenants: onlyX, Redirect: true,
		},
		{
			Method: "GET", Pattern: "/api/v1/auth/sso/callback",
			Path:    func(_ *authzFixtures, a *authzAttempt) string { return a.Obj["callback"] },
			Prepare: ssoCallbackPrepare, Want: everyone(), Tenants: onlyX, Redirect: true,
		},
		{
			Method: "POST", Pattern: "/api/v1/auth/refresh", Path: api("/auth/refresh"),
			Prepare: func(t *testing.T, f *authzFixtures, a *authzAttempt) { a.Obj["refresh"] = azRefreshToken(t, f.spare) },
			Body: func(_ *authzFixtures, a *authzAttempt) any {
				return map[string]string{"refresh_token": a.Obj["refresh"]}
			},
			Want: everyone(), Tenants: onlyX,
		},
		{
			Method: "POST", Pattern: "/api/v1/auth/sso/exchange", Path: api("/auth/sso/exchange"),
			Prepare: ssoCodePrepare,
			Body:    func(_ *authzFixtures, a *authzAttempt) any { return map[string]string{"code": a.Obj["code"]} },
			Want:    everyone(), Tenants: onlyX, Audit: audit.EventSSOExchange,
		},
		{
			Method: "POST", Pattern: "/api/v1/auth/logout", Path: api("/auth/logout"),
			Prepare: func(t *testing.T, f *authzFixtures, a *authzAttempt) { a.Obj["refresh"] = azRefreshToken(t, f.spare) },
			Body: func(_ *authzFixtures, a *authzAttempt) any {
				return map[string]string{"refresh_token": a.Obj["refresh"]}
			},
			Want: everyone(), Tenants: onlyX, Audit: audit.EventLogout, FreshSession: true,
		},
		{
			Method: "POST", Pattern: "/api/v1/auth/register", Path: api("/auth/register"),
			Body: func(f *authzFixtures, _ *authzAttempt) any {
				return map[string]string{"email": f.unique("register") + "@example.com", "password": "Az-" + randomHex(12)}
			},
			Want: everyone(), Tenants: onlyX, Audit: audit.EventRegister,
		},
		{
			Method: "POST", Pattern: "/api/v1/auth/login", Path: api("/auth/login"),
			Body: func(f *authzFixtures, _ *authzAttempt) any {
				return map[string]string{"email": f.spare.Email, "password": f.spare.Password}
			},
			Want: everyone(), Tenants: onlyX, Audit: audit.EventLogin,
		},
		{
			// Setup closes for good once an account exists; first-run setup
			// on an empty database is TestAuthzMatrixFirstRunSetup.
			Method: "POST", Pattern: "/api/v1/setup", Path: api("/setup"),
			Body: jsonBody(map[string]string{"token": "authz-guess", "email": "authz-setup@example.com", "password": "Az-setup-password-1"}),
			Want: sameFor(outcomeDeny404), Tenants: onlyX,
		},
		{
			Method: "POST", Pattern: "/api/v1/auth/reset", Path: api("/auth/reset"),
			Prepare: func(t *testing.T, _ *authzFixtures, a *authzAttempt) {
				a.Obj["reset"] = azResetToken(t, azRegister(t, "reset").UserID)
			},
			Body: func(_ *authzFixtures, a *authzAttempt) any {
				return map[string]string{"token": a.Obj["reset"], "password": "Az-" + randomHex(12)}
			},
			Want: everyone(), Tenants: onlyX, Audit: audit.EventResetPassword,
		},
		{
			// The token is the credential, so both tenants' links answer
			// every caller.
			Method: "GET", Pattern: "/api/v1/invites/{token}",
			Path: func(_ *authzFixtures, a *authzAttempt) string { return "/api/v1/invites/" + a.T.InviteToken },
			Want: everyone(), Foreign: everyone(),
		},
		{
			Method: "POST", Pattern: "/api/v1/invites/{token}/accept",
			Path: onObj("/api/v1/invites/", "token", "/accept"), Prepare: freshZInvite,
			Body: func(f *authzFixtures, _ *authzAttempt) any {
				return map[string]string{"email": f.unique("accept") + "@example.com", "password": "Az-" + randomHex(12)}
			},
			Want: everyone(), Tenants: onlyX, Audit: audit.EventAcceptInvite,
		},

		// The signed-in account's own profile: any working session, never a key.
		{Method: "GET", Pattern: "/api/v1/me", Path: api("/me"), Want: signedIn, Tenants: onlyX},
		{
			Method: "PUT", Pattern: "/api/v1/me", Path: api("/me"),
			Body: jsonBody(map[string]string{"display_name": "Authz Matrix"}),
			Want: signedIn, Tenants: onlyX, Audit: audit.EventUpdateProfile,
		},
		{
			// A password change ends the caller's other sessions and returns
			// a fresh one, which the After hook adopts.
			Method: "PUT", Pattern: "/api/v1/me/password", Path: api("/me/password"),
			Prepare: func(_ *testing.T, f *authzFixtures, a *authzAttempt) {
				a.Obj["current"] = f.callers[a.Caller].Password
				a.Obj["next"] = "Az-" + randomHex(12)
			},
			Body: func(_ *authzFixtures, a *authzAttempt) any {
				return map[string]string{"current_password": a.Obj["current"], "new_password": a.Obj["next"]}
			},
			After: func(t *testing.T, f *authzFixtures, a *authzAttempt, raw []byte) {
				var resp authResponse
				require.NoError(t, json.Unmarshal(raw, &resp))
				require.NotEmpty(t, resp.Token, "a password change returns a fresh session")
				p := f.callers[a.Caller]
				p.Password, p.Token = a.Obj["next"], resp.Token
			},
			Want: signedIn, Tenants: onlyX, Audit: audit.EventChangePassword, Destructive: true,
		},
		{Method: "GET", Pattern: "/api/v1/scanners", Path: api("/scanners"), Want: signedIn, Tenants: onlyX},

		// Instance administration: session admins only.
		{Method: "GET", Pattern: "/api/v1/users", Path: api("/users"), Want: instanceAdmin, Tenants: onlyX},
		{
			Method: "PUT", Pattern: "/api/v1/users/{id}/role", Path: onObj("/api/v1/users/", "user", "/role"),
			Prepare: freshUser("user"), Body: jsonBody(map[string]string{"role": "admin"}),
			Want: instanceAdmin, Tenants: onlyX, Audit: audit.EventChangeUserRole, Destructive: true,
		},
		{
			Method: "POST", Pattern: "/api/v1/users/{id}/reset-link", Path: onObj("/api/v1/users/", "user", "/reset-link"),
			Prepare: freshUser("user"), Want: instanceAdmin, Tenants: onlyX, Audit: audit.EventResetLink,
		},
		{
			Method: "POST", Pattern: "/api/v1/users/{id}/deactivate", Path: onObj("/api/v1/users/", "user", "/deactivate"),
			Prepare: freshUser("user"), Want: instanceAdmin, Tenants: onlyX, Audit: audit.EventDeactivateUser, Destructive: true,
		},
		{
			Method: "POST", Pattern: "/api/v1/users/{id}/reactivate", Path: onObj("/api/v1/users/", "user", "/reactivate"),
			Prepare: func(t *testing.T, _ *authzFixtures, a *authzAttempt) {
				a.Obj["user"] = azRegister(t, "inactive").UserID
				azSetActive(t, a.Obj["user"], false)
			},
			Want: instanceAdmin, Tenants: onlyX, Audit: audit.EventReactivateUser,
		},
		{Method: "GET", Pattern: "/api/v1/admin/status", Path: api("/admin/status"), Want: instanceAdmin, Tenants: onlyX},
		{
			Method: "GET", Pattern: "/api/v1/admin/retention/preview", Path: api("/admin/retention/preview?days=3650"),
			Want: instanceAdmin, Tenants: onlyX,
		},
		{
			// Ten years keeps every report of this run, so the purge is a
			// real authorized call that deletes nothing.
			Method: "POST", Pattern: "/api/v1/admin/retention/purge", Path: api("/admin/retention/purge"),
			Body: jsonBody(map[string]int{"older_than_days": 3650}),
			Want: instanceAdmin, Tenants: onlyX, Audit: audit.EventPurgeRetention, Destructive: true,
		},
		{Method: "GET", Pattern: "/api/v1/watcher/status", Path: api("/watcher/status"), Want: instanceAdmin, Tenants: onlyX},

		// Projects.
		{
			// A key sees its own project; a session sees its memberships. The
			// ingest-only key fails the read scope.
			Method: "GET", Pattern: "/api/v1/projects", Path: api("/projects"),
			Want: allowOnly(append([]authzCaller{callerKeyRead}, sessions...)...), Tenants: onlyX,
		},
		{
			Method: "POST", Pattern: "/api/v1/projects", Path: api("/projects"),
			Body: func(f *authzFixtures, _ *authzAttempt) any {
				slug := f.unique("proj")
				return map[string]string{"name": slug, "slug": slug}
			},
			Want: instanceAdmin, Tenants: onlyX, Audit: audit.EventCreateProject,
		},
		{Method: "GET", Pattern: "/api/v1/projects/{slug}", Path: inProject(""), Want: readers},
		{
			Method: "PUT", Pattern: "/api/v1/projects/{slug}", Path: inProject(""),
			Body: jsonBody(map[string]string{"description": "authz matrix"}),
			Want: sessionAdmins, Audit: audit.EventUpdateProject,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/projects/{slug}", Path: onObj("/api/v1/projects/", "slug", ""),
			Prepare: freshProject, Want: sessionAdmins, Audit: audit.EventDeleteProject, Destructive: true,
		},
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/findings", Path: inProject("/findings"), Want: readers},
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/reports", Path: inProject("/reports"), Want: readers},
		{
			Method: "GET", Pattern: "/api/v1/reports/{id}",
			Path: func(_ *authzFixtures, a *authzAttempt) string { return "/api/v1/reports/" + a.T.ReportID },
			Want: readers,
		},
		{
			// Ingest: the ingest-scoped key and managers; the admin scope does
			// not imply ingest.
			Method: "POST", Pattern: "/api/v1/reports", Path: api("/reports"),
			Body: func(f *authzFixtures, a *authzAttempt) any {
				return f.ingestBody(a.T.Slug, f.nextCommit(), "authz-ingest")
			},
			Want: allowOnly(callerKeyIngest, callerManager, callerInstanceAdmin, callerProjectAdmin), Audit: audit.EventIngestReport,
		},

		// Project API keys: managers, and a key holding the admin scope.
		{
			Method: "POST", Pattern: "/api/v1/auth/apikeys", Path: api("/auth/apikeys"),
			Body: func(f *authzFixtures, a *authzAttempt) any {
				return map[string]string{"project": a.T.Slug, "name": f.unique("minted")}
			},
			Want: writers, Audit: audit.EventCreateAPIKey,
		},
		{
			Method: "GET", Pattern: "/api/v1/auth/apikeys",
			Path: func(_ *authzFixtures, a *authzAttempt) string { return "/api/v1/auth/apikeys?project=" + a.T.Slug },
			Want: writers,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/auth/apikeys/{id}",
			Path: func(_ *authzFixtures, a *authzAttempt) string {
				return "/api/v1/auth/apikeys/" + a.Obj["key"] + "?project=" + a.T.Slug
			},
			Prepare: freshKey, Want: writers, Audit: audit.EventRevokeAPIKey, Destructive: true,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/auth/apikeys/{id}", Variant: "x-project-y-key",
			Path: func(f *authzFixtures, a *authzAttempt) string {
				return "/api/v1/auth/apikeys/" + a.Obj["key"] + "?project=" + f.X.Slug
			},
			Prepare: freshYKey, Want: mixedPair(writers, projectWriters...), Tenants: onlyX, Destructive: true,
		},

		// Policy templates are instance-wide.
		{Method: "GET", Pattern: "/api/v1/policy-templates", Path: api("/policy-templates"), Want: signedIn, Tenants: onlyX},
		{
			Method: "POST", Pattern: "/api/v1/policy-templates", Path: api("/policy-templates"),
			Body: func(f *authzFixtures, _ *authzAttempt) any {
				return map[string]any{"name": f.unique("template"), "definition": map[string]string{"severity_floor": "high"}}
			},
			Want: instanceAdmin, Tenants: onlyX, Audit: audit.EventCreatePolicyTemplate,
		},
		{
			Method: "PUT", Pattern: "/api/v1/policy-templates/{id}",
			Path: func(f *authzFixtures, _ *authzAttempt) string { return "/api/v1/policy-templates/" + f.templateID },
			Body: func(f *authzFixtures, _ *authzAttempt) any {
				return map[string]any{"name": f.templateName, "description": "authz", "definition": map[string]string{"severity_floor": "high"}}
			},
			Want: instanceAdmin, Tenants: onlyX, Audit: audit.EventUpdatePolicyTemplate,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/policy-templates/{id}", Path: onObj("/api/v1/policy-templates/", "template", ""),
			Prepare: freshTemplate, Want: instanceAdmin, Tenants: onlyX, Audit: audit.EventDeletePolicyTemplate,
		},
		{
			Method: "PUT", Pattern: "/api/v1/projects/{slug}/policy", Path: inProject("/policy"),
			Body: func(f *authzFixtures, _ *authzAttempt) any { return map[string]string{"template_name": f.templateName} },
			Want: sessionAdmins, Audit: audit.EventSetProjectPolicy,
		},
		{
			Method: "PUT", Pattern: "/api/v1/projects/{slug}/policy/overrides", Path: inProject("/policy/overrides"),
			Body: jsonBody(map[string]any{"overrides": map[string]string{"severity_floor": "high"}}),
			Want: sessionAdmins, Audit: audit.EventSetPolicyOverrides,
		},
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/policy", Path: inProject("/policy"), Want: readers},

		// Teams. The directory lists the teams a caller belongs to or that are
		// linked to a project they reach (C5 gets an empty one). A team outside
		// that set answers 404, like a missing team, on reads and on roster
		// writes; team rosters change by team admins only.
		{Method: "GET", Pattern: "/api/v1/teams", Path: api("/teams"), Want: signedIn, Tenants: onlyX},
		{
			Method: "POST", Pattern: "/api/v1/teams", Path: api("/teams"),
			Body: func(f *authzFixtures, _ *authzAttempt) any { return map[string]string{"name": f.unique("team")} },
			Want: instanceAdmin, Tenants: onlyX, Audit: audit.EventCreateTeam,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/teams/{id}", Path: onObj("/api/v1/teams/", "team", ""),
			Prepare: func(t *testing.T, f *authzFixtures, a *authzAttempt) { a.Obj["team"] = azTeam(t, f) },
			Want:    instanceAdmin, Tenants: onlyX, Audit: audit.EventDeleteTeam, Destructive: true,
		},
		{
			Method: "GET", Pattern: "/api/v1/teams/{id}/members",
			Path: func(_ *authzFixtures, a *authzAttempt) string { return "/api/v1/teams/" + a.T.TeamOwned + "/members" },
			// TeamOwned is linked to no project and C11 is its only non-admin member.
			Want:    with(allowOnly(callerTeamAdmin, callerInstanceAdmin), outcomeDeny404, callerNoProject, callerMember, callerManager, callerProjectAdmin, callerTeamMember),
			Foreign: with(allowOnly(callerInstanceAdmin), outcomeDeny404, callerNoProject, callerMember, callerManager, callerProjectAdmin, callerTeamMember, callerTeamAdmin),
		},
		{
			Method: "POST", Pattern: "/api/v1/teams/{id}/members",
			Path: func(_ *authzFixtures, a *authzAttempt) string { return "/api/v1/teams/" + a.T.TeamOwned + "/members" },
			Body: func(f *authzFixtures, _ *authzAttempt) any {
				return map[string]string{"user_id": f.spare.UserID, "role": "member"}
			},
			Want:    teamRosterWriters,
			Foreign: teamRosterWritersForeign, Audit: audit.EventAddTeamMember,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/teams/{id}/members/{userID}",
			Path: func(_ *authzFixtures, a *authzAttempt) string {
				return "/api/v1/teams/" + a.Obj["team"] + "/members/" + a.Obj["user"]
			},
			Prepare: freshTeamMember(func(tn *authzTenant) string { return tn.TeamOwned }),
			Want:    teamRosterWriters,
			Foreign: teamRosterWritersForeign, Audit: audit.EventRemoveTeamMember,
		},
		{
			// A project admin of X does not administer the team linked to X.
			Method: "DELETE", Pattern: "/api/v1/teams/{id}/members/{userID}", Variant: "linked-team",
			Path: func(_ *authzFixtures, a *authzAttempt) string {
				return "/api/v1/teams/" + a.Obj["team"] + "/members/" + a.Obj["user"]
			},
			Prepare: freshTeamMember(func(tn *authzTenant) string { return tn.TeamLinked }),
			// C5 and C11 reach no project, so the team linked to X is invisible
			// to them and answers like a missing team.
			Want:    with(instanceAdmin, outcomeDeny404, callerNoProject, callerTeamAdmin),
			Tenants: onlyX, Audit: audit.EventRemoveTeamMember,
		},
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/teams", Path: inProject("/teams"), Want: readers},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/teams", Path: inProject("/teams"),
			Body: func(_ *authzFixtures, a *authzAttempt) any {
				return map[string]string{"team_id": a.T.TeamLinkTarget, "role": "member"}
			},
			Want: sessionManagers, Audit: audit.EventLinkProjectTeam,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/projects/{slug}/teams/{teamID}", Path: projectObj("/teams/", "team", ""),
			Prepare: freshLinkedTeam, Want: sessionManagers, Audit: audit.EventUnlinkProjectTeam,
		},

		// Findings.
		{Method: "GET", Pattern: "/api/v1/findings/{id}", Path: onFinding(""), Want: readers},
		{
			Method: "PATCH", Pattern: "/api/v1/findings/{id}", Path: onFinding(""), Prepare: triagePrepare,
			Body: func(_ *authzFixtures, a *authzAttempt) any {
				return map[string]string{"analysis_state": a.Obj["state"], "reason": "authz matrix"}
			},
			Want: writers, Audit: audit.EventTriageFinding + ",db:analysis_changed",
		},
		{
			Method: "POST", Pattern: "/api/v1/findings/{id}/analysis/undo", Path: onFinding("/analysis/undo"),
			Prepare: undoPrepare,
			Body:    func(_ *authzFixtures, a *authzAttempt) any { return map[string]string{"event_id": a.Obj["event"]} },
			Want:    writers, Audit: audit.EventUndoTriage + ",db:analysis_changed",
		},
		{
			Method: "POST", Pattern: "/api/v1/findings/{id}/verify", Path: onFinding("/verify"),
			Want: writers, Audit: audit.EventVerifyFix,
		},
		{Method: "GET", Pattern: "/api/v1/findings/{id}/patch-preview", Path: onFinding("/patch-preview"), Want: readers},
		{
			Method: "GET", Pattern: "/api/v1/findings/{id}/notify-preview",
			Path: onFinding("/notify-preview?channel=issue&target=tracker:authz"), Want: readers,
		},
		{
			Method: "POST", Pattern: "/api/v1/findings/bulk-analysis", Path: api("/findings/bulk-analysis"),
			Body: func(_ *authzFixtures, a *authzAttempt) any {
				return map[string]any{"finding_ids": []string{a.T.FindingID, a.T.Finding2ID}, "analysis_state": "in_triage", "reason": "authz matrix"}
			},
			Want: writers, Audit: audit.EventBulkTriage,
		},
		{
			// One batch naming an X finding and a Y finding: a manager of X
			// only must be refused as a whole, with nothing written.
			Method: "POST", Pattern: "/api/v1/findings/bulk-analysis", Variant: "mixed-tenants", Path: api("/findings/bulk-analysis"),
			Body: func(f *authzFixtures, _ *authzAttempt) any {
				return map[string]any{"finding_ids": []string{f.X.Finding2ID, f.Y.Finding2ID}, "analysis_state": "exploitable", "reason": "authz mixed"}
			},
			Want: instanceAdmin, Tenants: onlyX, Audit: audit.EventBulkTriage,
		},
		{Method: "GET", Pattern: "/api/v1/findings/{id}/events", Path: onFinding("/events"), Want: readers},
		{
			// The fixture finding comes from a SARIF report and carries no CVE,
			// so a caller who passes the access check gets 404 not_cve; the
			// check runs first (usecase.GetFindingCVE).
			Method: "GET", Pattern: "/api/v1/findings/{id}/cve", Path: onFinding("/cve"), Want: readers,
			AllowCodes: []int{http.StatusNotFound}, AllowError: "not_cve",
		},
		{
			Method: "POST", Pattern: "/api/v1/findings/{findingID}/evidence", Path: onFinding("/evidence"),
			Body: jsonBody(map[string]string{"type": "reference", "url": "https://example.com/authz", "description": "authz matrix"}),
			Want: writers, Audit: audit.EventCreateEvidence,
		},
		{Method: "GET", Pattern: "/api/v1/findings/{findingID}/evidence", Path: onFinding("/evidence"), Want: readers},
		{
			Method: "DELETE", Pattern: "/api/v1/findings/{findingID}/evidence/{evidenceID}",
			Path: func(_ *authzFixtures, a *authzAttempt) string {
				return "/api/v1/findings/" + a.T.FindingID + "/evidence/" + a.Obj["evidence"]
			},
			Prepare: freshEvidence, Want: writers, Audit: audit.EventDeleteEvidence,
		},
		{
			// X's finding in the path, Y's evidence id: the pair does not
			// exist, whoever asks.
			Method: "DELETE", Pattern: "/api/v1/findings/{findingID}/evidence/{evidenceID}", Variant: "x-finding-y-evidence",
			Path: func(f *authzFixtures, a *authzAttempt) string {
				return "/api/v1/findings/" + f.X.FindingID + "/evidence/" + a.Obj["evidence"]
			},
			Prepare: freshYEvidence, Want: mixedPair(writers, projectWriters...), Tenants: onlyX,
		},
		{
			Method: "POST", Pattern: "/api/v1/findings/{findingID}/reachability", Path: onFinding("/reachability"),
			Body: jsonBody(map[string]string{"state": "reachable", "evidence": "authz matrix"}),
			Want: writers, Audit: audit.EventAssessReachability,
		},
		{Method: "GET", Pattern: "/api/v1/findings/{findingID}/reachability", Path: onFinding("/reachability"), Want: readers},
		{
			Method: "POST", Pattern: "/api/v1/findings/{findingID}/signoff", Path: onFinding("/signoff"),
			Body: jsonBody(map[string]string{"status": "pending", "comment": "authz matrix"}),
			Want: writers, Audit: audit.EventSignoffFinding,
		},
		{Method: "GET", Pattern: "/api/v1/findings/{findingID}/signoff", Path: onFinding("/signoff"), Want: readers},

		// Gate and pull-request check.
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/gate", Path: inProject("/gate"), Want: readers},
		{
			Method: "GET", Pattern: "/api/v1/projects/{slug}/gate", Variant: "introduced-own-report",
			Path: func(_ *authzFixtures, a *authzAttempt) string {
				return "/api/v1/projects/" + a.T.Slug + "/gate?introduced_only=1&report_id=" + a.T.ReportID
			},
			Want: readers,
		},
		{
			// A foreign report id must not evaluate, or list, another
			// tenant's findings under X's name.
			Method: "GET", Pattern: "/api/v1/projects/{slug}/gate", Variant: "introduced-foreign-report",
			Path: func(f *authzFixtures, _ *authzAttempt) string {
				return "/api/v1/projects/" + f.X.Slug + "/gate?introduced_only=1&report_id=" + f.Y.ReportID
			},
			Want: allowOnly(), Tenants: onlyX,
		},
		{
			Method: "GET", Pattern: "/api/v1/projects/{slug}/pr-check",
			Path: inProject("/pr-check?provider=github&commit=" + authzCommit), Want: readers,
		},
		{
			Method: "GET", Pattern: "/api/v1/projects/{slug}/pr-check", Variant: "foreign-report",
			Path: func(f *authzFixtures, _ *authzAttempt) string {
				return "/api/v1/projects/" + f.X.Slug + "/pr-check?provider=github&commit=" + authzCommit + "&report_id=" + f.Y.ReportID
			},
			Want: allowOnly(), Tenants: onlyX,
		},

		// Context, settings and insights.
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/environments", Path: inProject("/environments"), Want: readers},
		{
			Method: "PUT", Pattern: "/api/v1/projects/{slug}/environments/{id}",
			Path: func(_ *authzFixtures, a *authzAttempt) string {
				return "/api/v1/projects/" + a.T.Slug + "/environments/" + a.T.EnvID
			},
			Body: jsonBody(map[string]any{"tier": "production", "internet_facing": true, "data_sensitivity": "internal"}),
			Want: sessionAdmins, Audit: audit.EventUpdateEnvironment,
		},
		{
			Method: "PUT", Pattern: "/api/v1/projects/{slug}/environments/{id}", Variant: "x-slug-y-environment",
			Path: func(f *authzFixtures, _ *authzAttempt) string {
				return "/api/v1/projects/" + f.X.Slug + "/environments/" + f.Y.EnvID
			},
			Body: jsonBody(map[string]any{"tier": "test", "internet_facing": false, "data_sensitivity": "public"}),
			Want: mixedPair(sessionAdmins, projectAdmins...), Tenants: onlyX,
		},
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/targets", Path: inProject("/targets"), Want: readers},
		{
			Method: "DELETE", Pattern: "/api/v1/projects/{slug}/reports/{id}", Path: projectObj("/reports/", "report", ""),
			Prepare: freshReport, Want: sessionAdmins, Audit: audit.EventDeleteReport, Destructive: true,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/projects/{slug}/reports/{id}", Variant: "x-slug-y-report",
			Path:    xSlugObj("/reports/", "report", ""),
			Prepare: freshYReport, Want: mixedPair(sessionAdmins, projectAdmins...), Tenants: onlyX, Destructive: true,
		},
		{
			Method: "GET", Pattern: "/api/v1/projects/{slug}/reports/{id}/deletion-preview",
			Path: projectObj("/reports/", "report", "/deletion-preview"), Prepare: freshReport, Want: sessionAdmins,
		},
		{
			Method: "GET", Pattern: "/api/v1/projects/{slug}/reports/{id}/deletion-preview", Variant: "x-slug-y-report",
			Path: xSlugObj("/reports/", "report", "/deletion-preview"), Prepare: freshYReport,
			Want: mixedPair(sessionAdmins, projectAdmins...), Tenants: onlyX,
		},
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/watcher", Path: inProject("/watcher"), Want: readers},
		{
			Method: "PUT", Pattern: "/api/v1/projects/{slug}/watcher", Path: inProject("/watcher"),
			Body: jsonBody(map[string]any{"enabled": false}),
			Want: sessionAdmins, Audit: audit.EventUpdateWatcher,
		},
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/stats", Path: inProject("/stats"), Want: readers},
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/aging", Path: inProject("/aging"), Want: readers},
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/artifacts", Path: inProject("/artifacts"), Want: readers},

		// Invites and members.
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/invites", Path: inProject("/invites"), Want: sessionManagers},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/invites", Path: inProject("/invites"),
			Body: jsonBody(map[string]string{"role": "member"}), Want: sessionManagers, Audit: audit.EventCreateInvite,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/projects/{slug}/invites/{id}", Path: projectObj("/invites/", "invite", ""),
			Prepare: freshInvite, Want: sessionManagers, Audit: audit.EventRevokeInvite,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/projects/{slug}/invites/{id}", Variant: "x-slug-y-invite",
			Path:    xSlugObj("/invites/", "invite", ""),
			Prepare: freshYInvite, Want: mixedPair(sessionManagers, managers...), Tenants: onlyX,
		},
		{
			// Redeeming adds the caller to scratch project Z, so the row runs
			// with the destructive ones.
			Method: "POST", Pattern: "/api/v1/invites/{token}/join", Path: onObj("/api/v1/invites/", "token", "/join"),
			Prepare: freshZInvite, Want: signedIn, Tenants: onlyX, Audit: audit.EventAcceptInvite, Destructive: true,
		},
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/members", Path: inProject("/members"), Want: readers},
		{
			Method: "GET", Pattern: "/api/v1/projects/{slug}/member-suggestions", Path: inProject("/member-suggestions?q=authz"),
			Want: sessionManagers,
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/members", Path: inProject("/members"),
			Body: func(f *authzFixtures, _ *authzAttempt) any {
				return map[string]string{"user_id": f.spare.UserID, "role": "member"}
			},
			Want: sessionManagers, Audit: audit.EventAddProjectMember,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/projects/{slug}/members/{userID}", Path: projectObj("/members/", "user", ""),
			Prepare: freshMember, Want: sessionManagers, Audit: audit.EventRemoveProjectMember,
		},

		// Waivers.
		{Method: "GET", Pattern: "/api/v1/projects/{slug}/waivers", Path: inProject("/waivers"), Want: readers},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/waivers", Path: inProject("/waivers"),
			Body: func(f *authzFixtures, a *authzAttempt) any {
				return map[string]any{"name": f.unique("waiver"), "description": "authz matrix", "target_ids": []string{a.T.Finding2ID}}
			},
			Want: writers, Audit: audit.EventCreateWaiver + ",db:created",
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/waivers/requests", Path: inProject("/waivers/requests"),
			Prepare: func(t *testing.T, f *authzFixtures, a *authzAttempt) { f.clearPendingRequests(t, a.T) },
			Body:    requestBody, Want: allowOnly(projectSessions...), Audit: audit.EventRequestWaiver + ",db:requested",
		},
		{
			Method: "GET", Pattern: "/api/v1/projects/{slug}/waivers/{id}",
			Path: func(_ *authzFixtures, a *authzAttempt) string {
				return "/api/v1/projects/" + a.T.Slug + "/waivers/" + a.T.WaiverID
			},
			Want: readers,
		},
		{
			Method: "GET", Pattern: "/api/v1/projects/{slug}/waivers/{id}", Variant: "x-slug-y-waiver",
			Path: func(f *authzFixtures, _ *authzAttempt) string {
				return "/api/v1/projects/" + f.X.Slug + "/waivers/" + f.Y.WaiverID
			},
			Want: mixedPair(readers, projectReaders...), Tenants: onlyX,
		},
		{
			Method: "PUT", Pattern: "/api/v1/projects/{slug}/waivers/{id}",
			Path: func(_ *authzFixtures, a *authzAttempt) string {
				return "/api/v1/projects/" + a.T.Slug + "/waivers/" + a.T.WaiverID
			},
			Body: jsonBody(map[string]string{"description": "authz matrix update"}),
			Want: writers, Audit: audit.EventUpdateWaiver + ",db:updated",
		},
		{
			Method: "PUT", Pattern: "/api/v1/projects/{slug}/waivers/{id}", Variant: "x-slug-y-waiver",
			Path: xSlugObj("/waivers/", "waiver", ""), Prepare: freshYWaiver,
			Body: jsonBody(map[string]string{"description": "authz mixed"}),
			Want: mixedPair(writers, projectWriters...), Tenants: onlyX,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/projects/{slug}/waivers/{id}", Path: projectObj("/waivers/", "waiver", ""),
			Prepare: freshWaiver, Want: writers, Audit: audit.EventDeleteWaiver,
		},
		{
			Method: "DELETE", Pattern: "/api/v1/projects/{slug}/waivers/{id}", Variant: "x-slug-y-waiver",
			Path: xSlugObj("/waivers/", "waiver", ""), Prepare: freshYWaiver,
			Want: mixedPair(writers, projectWriters...), Tenants: onlyX,
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/waivers/{id}/toggle", Path: projectObj("/waivers/", "waiver", "/toggle"),
			Prepare: freshWaiver, Want: writers, Audit: audit.EventToggleWaiver + ",db:disabled",
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/waivers/{id}/revoke", Path: projectObj("/waivers/", "waiver", "/revoke"),
			Prepare: freshWaiver, Body: jsonBody(map[string]any{}), Want: writers, Audit: audit.EventRevokeWaiver + ",db:revoked",
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/waivers/{id}/revoke", Variant: "x-slug-y-waiver",
			Path: xSlugObj("/waivers/", "waiver", "/revoke"), Prepare: freshYWaiver, Body: jsonBody(map[string]any{}),
			Want: mixedPair(writers, projectWriters...), Tenants: onlyX,
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/waivers/{id}/restore", Path: projectObj("/waivers/", "waiver", "/restore"),
			Prepare: revokedWaiver, Body: jsonBody(map[string]any{}), Want: writers, Audit: audit.EventRestoreWaiver + ",db:restored",
		},
		{
			// The requester (C6 in X) cannot decide on their own request.
			Method: "POST", Pattern: "/api/v1/projects/{slug}/waivers/{id}/approve", Path: projectObj("/waivers/", "waiver", "/approve"),
			Prepare: pendingWaiver, Body: jsonBody(map[string]string{"note": "authz approve"}),
			Want: sessionManagers, Audit: audit.EventApproveWaiver + ",db:approved",
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/waivers/{id}/approve", Variant: "x-slug-y-waiver",
			Path: xSlugObj("/waivers/", "waiver", "/approve"), Prepare: pendingYWaiver,
			Body: jsonBody(map[string]string{"note": "authz mixed"}),
			Want: mixedPair(sessionManagers, managers...), Tenants: onlyX,
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/waivers/{id}/reject", Path: projectObj("/waivers/", "waiver", "/reject"),
			Prepare: pendingWaiver, Body: jsonBody(map[string]string{"note": "authz reject"}),
			Want: sessionManagers, Audit: audit.EventRejectWaiver + ",db:rejected",
		},
		{
			// Only the requester takes a request back, the instance admin
			// included.
			Method: "POST", Pattern: "/api/v1/projects/{slug}/waivers/{id}/withdraw", Path: projectObj("/waivers/", "waiver", "/withdraw"),
			Prepare: pendingWaiver, Want: allowOnly(callerMember), Foreign: allowOnly(),
			Audit: audit.EventWithdrawWaiver + ",db:withdrawn",
		},
		{
			Method: "GET", Pattern: "/api/v1/projects/{slug}/waivers/{id}/events",
			Path: func(_ *authzFixtures, a *authzAttempt) string {
				return "/api/v1/projects/" + a.T.Slug + "/waivers/" + a.T.WaiverID + "/events"
			},
			Want: readers,
		},
		{
			Method: "GET", Pattern: "/api/v1/projects/{slug}/waivers/{id}/events", Variant: "x-slug-y-waiver",
			Path: func(f *authzFixtures, _ *authzAttempt) string {
				return "/api/v1/projects/" + f.X.Slug + "/waivers/" + f.Y.WaiverID + "/events"
			},
			Want: mixedPair(readers, projectReaders...), Tenants: onlyX,
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/waivers/check-match", Path: inProject("/waivers/check-match"),
			Body: func(_ *authzFixtures, a *authzAttempt) any { return map[string]string{"finding_id": a.T.FindingID} },
			Want: readers,
		},
		{
			Method: "POST", Pattern: "/api/v1/projects/{slug}/waivers/check-match", Variant: "foreign-finding",
			Path: func(f *authzFixtures, _ *authzAttempt) string {
				return "/api/v1/projects/" + f.X.Slug + "/waivers/check-match"
			},
			Body: func(f *authzFixtures, _ *authzAttempt) any { return map[string]string{"finding_id": f.Y.FindingID} },
			Want: allowOnly(), Tenants: onlyX,
		},
	}
}
