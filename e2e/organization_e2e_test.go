//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Local response shapes for the organization endpoints.

type projectEnvelope struct {
	ID          string  `json:"id"`
	Slug        string  `json:"slug"`
	Name        string  `json:"name"`
	Description *string `json:"description"`
}

type memberResponse struct {
	ProjectID string `json:"project_id"`
	UserID    string `json:"user_id"`
	Role      string `json:"role"`
}

type teamResponse struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type teamMemberResponse struct {
	TeamID    string `json:"team_id"`
	UserID    string `json:"user_id"`
	UserEmail string `json:"user_email"`
	Role      string `json:"role"`
}

type projectTeamResponse struct {
	ProjectID string `json:"project_id"`
	TeamID    string `json:"team_id"`
	TeamName  string `json:"team_name"`
	Role      string `json:"role"`
}

type scannerDescriptor struct {
	Name             string   `json:"name"`
	Version          string   `json:"version"`
	FindingKinds     []string `json:"finding_kinds"`
	ProvidesPackages bool     `json:"provides_packages"`
}

// listProjectSlugs returns the slugs visible to one identity — the tenant
// visibility contract of GET /api/v1/projects.
func listProjectSlugs(t *testing.T, token string) []string {
	t.Helper()
	projects := request[[]projectEnvelope](t, http.MethodGet, "/api/v1/projects", token, nil, http.StatusOK)
	slugs := make([]string, 0, len(projects))
	for _, p := range projects {
		slugs = append(slugs, p.Slug)
	}
	return slugs
}

// errorCode decodes an error response body and returns its code.
func errorCode(t *testing.T, raw []byte) string {
	t.Helper()
	var e apiError
	require.NoErrorf(t, json.Unmarshal(raw, &e), "decode error body: %s", raw)
	return e.Error.Code
}

// TestE2E_ProjectLifecycle walks a project's full lifecycle and the
// identity-scoped visibility rules around it: lists differ per principal,
// missing projects leak nothing to non-members, updates are admin-gated,
// duplicate slugs conflict, and delete removes the project for everyone.
func TestE2E_ProjectLifecycle(t *testing.T) {
	slug := newProject(t, "org-crud")
	key := mintKey(t, slug)
	viewerToken := login(t, "e2e-viewer@example.com", adminPass)

	t.Run("project lists are scoped by identity", func(t *testing.T) {
		require.Contains(t, listProjectSlugs(t, adminToken), slug,
			"a global admin sees every project")

		keySlugs := listProjectSlugs(t, key)
		require.Equal(t, []string{slug}, keySlugs,
			"a project API key sees exactly its own project")

		require.NotContains(t, listProjectSlugs(t, viewerToken), slug,
			"a viewer with no membership sees none of the project")
	})

	t.Run("reads and missing projects leak nothing to non-members", func(t *testing.T) {
		got := request[projectEnvelope](t, http.MethodGet, "/api/v1/projects/"+slug, adminToken, nil, http.StatusOK)
		require.Equal(t, slug, got.Slug)
		require.NotEmpty(t, got.Name)

		status, raw := doJSON(t, http.MethodGet, "/api/v1/projects/"+slug, viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw))

		missing := "e2e-missing-" + randomHex(4)
		status, raw = doJSON(t, http.MethodGet, "/api/v1/projects/"+missing, adminToken, nil)
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw),
			"a global admin learns the project is missing")

		status, raw = doJSON(t, http.MethodGet, "/api/v1/projects/"+missing, viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"a non-member must not learn whether the project exists")
	})

	t.Run("update renames and rewrites the description", func(t *testing.T) {
		renamed := slug + "-renamed"
		first := "first draft"
		updated := request[projectEnvelope](t, http.MethodPut, "/api/v1/projects/"+slug, adminToken,
			map[string]any{"name": renamed, "description": first}, http.StatusOK)
		require.Equal(t, slug, updated.Slug, "the slug is immutable")
		require.Equal(t, renamed, updated.Name)
		require.NotNil(t, updated.Description)
		require.Equal(t, first, *updated.Description)

		got := request[projectEnvelope](t, http.MethodGet, "/api/v1/projects/"+slug, adminToken, nil, http.StatusOK)
		require.Equal(t, renamed, got.Name)
		require.NotNil(t, got.Description)

		// A blank description clears it; a nil field would leave it alone.
		cleared := request[projectEnvelope](t, http.MethodPut, "/api/v1/projects/"+slug, adminToken,
			map[string]any{"description": ""}, http.StatusOK)
		require.Nil(t, cleared.Description, "a blank description clears the value")

		status, raw := doJSON(t, http.MethodPut, "/api/v1/projects/"+slug, adminToken, map[string]any{})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "missing_field", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPut, "/api/v1/projects/"+slug, viewerToken,
			map[string]any{"name": "viewer rename"})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"a non-member session cannot rename")

		status, raw = doJSON(t, http.MethodPut, "/api/v1/projects/"+slug, key,
			map[string]any{"name": "key rename"})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_scope", errorCode(t, raw),
			"a project key without admin scope cannot rename")
	})

	t.Run("duplicate slugs conflict instead of failing", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/projects", adminToken,
			map[string]string{"name": "duplicate", "slug": slug})
		require.Equal(t, http.StatusConflict, status)
		require.Equal(t, "slug_taken", errorCode(t, raw))
	})

	t.Run("unroutable slugs are rejected", func(t *testing.T) {
		for _, bad := range []string{"my.app", "Upper-Case", "api", "login", "ab"} {
			status, raw := doJSON(t, http.MethodPost, "/api/v1/projects", adminToken,
				map[string]string{"name": "bad slug", "slug": bad})
			require.Equal(t, http.StatusBadRequest, status, bad)
			require.Equal(t, "invalid_slug", errorCode(t, raw), bad)
		}
	})

	t.Run("delete removes the project for everyone", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodDelete, "/api/v1/projects/"+slug, viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodDelete, "/api/v1/projects/"+slug, key, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_scope", errorCode(t, raw),
			"a project key without admin scope cannot delete")

		deleted := request[projectEnvelope](t, http.MethodDelete, "/api/v1/projects/"+slug, adminToken, nil, http.StatusOK)
		require.Equal(t, slug, deleted.Slug, "the deleted project is returned for audit")

		status, raw = doJSON(t, http.MethodGet, "/api/v1/projects/"+slug, adminToken, nil)
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw))

		status, _ = doJSON(t, http.MethodDelete, "/api/v1/projects/"+slug, adminToken, nil)
		require.Equal(t, http.StatusNotFound, status, "deleting twice reports the loss")
	})
}

// TestE2E_ProjectMembership pins the membership business process:
// the roster is admin-only, grants validate identity/role/user, membership
// unlocks reads, and the project role gates writes (viewer reads but cannot
// ingest; an editor grant unlocks ingest).
func TestE2E_ProjectMembership(t *testing.T) {
	slug := newProject(t, "org-members")
	viewerToken := login(t, "e2e-viewer@example.com", adminPass)
	adminMe := request[userProfile](t, http.MethodGet, "/api/v1/me", adminToken, nil, http.StatusOK)
	viewerMe := request[userProfile](t, http.MethodGet, "/api/v1/me", viewerToken, nil, http.StatusOK)

	t.Run("roster is admin-only and starts with the creator", func(t *testing.T) {
		members := request[[]memberResponse](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/members", adminToken, nil, http.StatusOK)
		require.Len(t, members, 1)
		require.Equal(t, adminMe.ID, members[0].UserID)
		require.Equal(t, "admin", members[0].Role)

		status, raw := doJSON(t, http.MethodGet, "/api/v1/projects/"+slug+"/members", viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"membership rosters are project-admin only")
	})

	t.Run("a non-member has no access before a grant", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodGet, "/api/v1/projects/"+slug, viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw))

		status, _ = doJSON(t, http.MethodGet, "/api/v1/projects/"+slug+"/findings", viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)

		require.NotContains(t, listProjectSlugs(t, viewerToken), slug)

		status, raw = doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", viewerToken,
			map[string]string{"user_id": viewerMe.ID, "role": "viewer"})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"only project admins manage membership")
	})

	t.Run("membership writes validate fields, role, and user", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken, map[string]string{})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "missing_field", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
			map[string]string{"user_id": "not-a-uuid", "role": "viewer"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_id", errorCode(t, raw),
			"a user id that is not a UUID is a client error, not a server error")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
			map[string]string{"user_id": randomHex(16), "role": "viewer"})
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "user_not_found", errorCode(t, raw),
			"a well-formed id that belongs to nobody is reported as not found")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
			map[string]string{"user_id": viewerMe.ID, "role": "superuser"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_role", errorCode(t, raw),
			"roles outside admin/manager/member (or the legacy editor/viewer aliases) are refused")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
			map[string]string{"user_id": adminMe.ID, "role": "member"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "last_admin", errorCode(t, raw),
			"the only project admin cannot be demoted")
	})

	t.Run("a grant unlocks reads and roster visibility", func(t *testing.T) {
		added := request[memberResponse](t, http.MethodPost,
			"/api/v1/projects/"+slug+"/members", adminToken,
			map[string]string{"user_id": viewerMe.ID, "role": "member"}, http.StatusCreated)
		require.Equal(t, viewerMe.ID, added.UserID)
		require.Equal(t, "member", added.Role)
		require.Equal(t, slug != "", added.ProjectID != "")

		got := request[projectEnvelope](t, http.MethodGet, "/api/v1/projects/"+slug, viewerToken, nil, http.StatusOK)
		require.Equal(t, slug, got.Slug)

		findings := request[[]findingResponse](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/findings", viewerToken, nil, http.StatusOK)
		require.Empty(t, findings, "membership grants access, not data")

		require.Contains(t, listProjectSlugs(t, viewerToken), slug,
			"member visibility flows into the project list")

		members := request[[]memberResponse](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/members", viewerToken, nil, http.StatusOK)
		require.Len(t, members, 2, "a project member may view the roster")
	})

	t.Run("the project role gates writes", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/reports", viewerToken,
			ingestBody(t, slug, "medium.sarif.json"))
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"a member cannot ingest")

		upgraded := request[memberResponse](t, http.MethodPost,
			"/api/v1/projects/"+slug+"/members", adminToken,
			map[string]string{"user_id": viewerMe.ID, "role": "manager"}, http.StatusCreated)
		require.Equal(t, "manager", upgraded.Role,
			"re-granting the same user upserts the role")

		resp := request[ingestResponse](t, http.MethodPost, "/api/v1/reports", viewerToken,
			ingestBody(t, slug, "medium.sarif.json"), http.StatusCreated)
		require.Equal(t, 1, resp.TotalFindings,
			"a manager membership may ingest")

		findings := request[[]findingResponse](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/findings", viewerToken, nil, http.StatusOK)
		require.Len(t, findings, 1)
	})

	t.Run("removing a member revokes access", func(t *testing.T) {
		status, _ := doJSON(t, http.MethodDelete,
			"/api/v1/projects/"+slug+"/members/"+viewerMe.ID, adminToken, nil)
		require.Equal(t, http.StatusNoContent, status)

		status, _ = doJSON(t, http.MethodGet, "/api/v1/projects/"+slug, viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
	})
}

// TestE2E_TeamAccessGrants pins the team business process: any
// session may create a team but only global admins delete one, rosters are
// team-admin managed, and a project-team link confers access only while the
// user's team membership lasts (unlink, member removal, and team deletion
// each revoke it).
func TestE2E_TeamAccessGrants(t *testing.T) {
	slug := newProject(t, "org-team")
	viewerToken := login(t, "e2e-viewer@example.com", adminPass)
	viewerMe := request[userProfile](t, http.MethodGet, "/api/v1/me", viewerToken, nil, http.StatusOK)
	teamName := "e2e-team-" + randomHex(4)

	t.Run("creation and deletion are global-admin only", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/teams", viewerToken,
			map[string]string{"name": teamName + "-own"})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_role", errorCode(t, raw))

		team := request[teamResponse](t, http.MethodPost, "/api/v1/teams", adminToken,
			map[string]string{"name": teamName, "description": "e2e team"}, http.StatusCreated)
		require.Equal(t, teamName, team.Name)
		require.Equal(t, "e2e team", team.Description)

		statusCode, raw := doJSON(t, http.MethodPost, "/api/v1/teams", adminToken,
			map[string]string{"name": teamName})
		require.Equal(t, http.StatusConflict, statusCode)
		require.Equal(t, "team_conflict", errorCode(t, raw))

		statusCode, raw = doJSON(t, http.MethodPost, "/api/v1/teams", adminToken, map[string]string{"name": ""})
		require.Equal(t, http.StatusBadRequest, statusCode)
		require.Equal(t, "invalid_team", errorCode(t, raw))

		statusCode, raw = doJSON(t, http.MethodPost, "/api/v1/teams", adminToken,
			map[string]string{"name": strings.Repeat("a", 65)})
		require.Equal(t, http.StatusBadRequest, statusCode)
		require.Equal(t, "invalid_team", errorCode(t, raw))
	})

	// The list is global; find the team created above by name.
	teams := request[[]teamResponse](t, http.MethodGet, "/api/v1/teams", adminToken, nil, http.StatusOK)
	var found *teamResponse
	for i := range teams {
		if teams[i].Name == teamName {
			found = &teams[i]
		}
	}
	require.NotNil(t, found, "the created team must be listed")
	team := *found

	t.Run("rosters are team-admin managed", func(t *testing.T) {
		added := request[teamMemberResponse](t, http.MethodPost,
			"/api/v1/teams/"+team.ID+"/members", adminToken,
			map[string]string{"user_id": viewerMe.ID, "role": "member"}, http.StatusCreated)
		require.Equal(t, team.ID, added.TeamID)
		require.Equal(t, "member", added.Role)

		status, raw := doJSON(t, http.MethodPost, "/api/v1/teams/"+team.ID+"/members", adminToken,
			map[string]string{"user_id": viewerMe.ID, "role": "owner"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_role", errorCode(t, raw),
			"team roles are admin or member")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/teams/"+team.ID+"/members", adminToken,
			map[string]string{"user_id": randomHex(16), "role": "member"})
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "user_not_found", errorCode(t, raw),
			"an unknown user is refused without a server error")

		roster := request[[]teamMemberResponse](t, http.MethodGet,
			"/api/v1/teams/"+team.ID+"/members", adminToken, nil, http.StatusOK)
		require.Len(t, roster, 2, "creator (team admin) plus the added member")
		var member *teamMemberResponse
		for i := range roster {
			if roster[i].UserID == viewerMe.ID {
				member = &roster[i]
			}
		}
		require.NotNil(t, member, "the added member is listed")
		require.Equal(t, viewerMe.Email, member.UserEmail, "the roster carries the member email")
		require.Equal(t, "member", member.Role)

		status, raw = doJSON(t, http.MethodGet, "/api/v1/teams/"+team.ID+"/members", viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "forbidden", errorCode(t, raw),
			"a plain team member is not a team admin")
	})

	t.Run("a project-team link confers access only while membership lasts", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodGet, "/api/v1/projects/"+slug, viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.NotContains(t, listProjectSlugs(t, viewerToken), slug, "no link yet")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/teams", adminToken,
			map[string]string{"team_id": randomHex(16), "role": "viewer"})
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/teams", adminToken,
			map[string]string{"team_id": team.ID, "role": "superuser"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_link", errorCode(t, raw),
			"links confer admin, manager, or member")

		link := request[projectTeamResponse](t, http.MethodPost,
			"/api/v1/projects/"+slug+"/teams", adminToken,
			map[string]string{"team_id": team.ID, "role": "member"}, http.StatusCreated)
		require.Equal(t, team.ID, link.TeamID)
		require.Equal(t, teamName, link.TeamName)
		require.Equal(t, "member", link.Role)

		request[projectEnvelope](t, http.MethodGet, "/api/v1/projects/"+slug, viewerToken, nil, http.StatusOK)
		request[[]findingResponse](t, http.MethodGet, "/api/v1/projects/"+slug+"/findings", viewerToken, nil, http.StatusOK)
		require.Contains(t, listProjectSlugs(t, viewerToken), slug,
			"the link confers effective membership")
		links := request[[]projectTeamResponse](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/teams", adminToken, nil, http.StatusOK)
		require.Len(t, links, 1)

		status, _ = doJSON(t, http.MethodDelete,
			"/api/v1/projects/"+slug+"/teams/"+team.ID, adminToken, nil)
		require.Equal(t, http.StatusNoContent, status)
		require.Empty(t, request[[]projectTeamResponse](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/teams", adminToken, nil, http.StatusOK))
		status, _ = doJSON(t, http.MethodGet, "/api/v1/projects/"+slug, viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status,
			"unlinking revokes the conferred access")
		require.NotContains(t, listProjectSlugs(t, viewerToken), slug)

		request[projectTeamResponse](t, http.MethodPost,
			"/api/v1/projects/"+slug+"/teams", adminToken,
			map[string]string{"team_id": team.ID, "role": "member"}, http.StatusCreated)
		request[projectEnvelope](t, http.MethodGet, "/api/v1/projects/"+slug, viewerToken, nil, http.StatusOK)

		status, _ = doJSON(t, http.MethodDelete,
			"/api/v1/teams/"+team.ID+"/members/"+viewerMe.ID, adminToken, nil)
		require.Equal(t, http.StatusNoContent, status)
		status, _ = doJSON(t, http.MethodGet, "/api/v1/projects/"+slug, viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status,
			"dropping the team membership revokes access even with the link in place")

		request[teamMemberResponse](t, http.MethodPost,
			"/api/v1/teams/"+team.ID+"/members", adminToken,
			map[string]string{"user_id": viewerMe.ID, "role": "member"}, http.StatusCreated)
		request[projectEnvelope](t, http.MethodGet, "/api/v1/projects/"+slug, viewerToken, nil, http.StatusOK)

		status, _ = doJSON(t, http.MethodDelete, "/api/v1/teams/"+team.ID, adminToken, nil)
		require.Equal(t, http.StatusNoContent, status,
			"a global admin deletes the team")
		require.Empty(t, request[[]projectTeamResponse](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/teams", adminToken, nil, http.StatusOK),
			"deleting the team cascades its project links away")
		status, _ = doJSON(t, http.MethodGet, "/api/v1/projects/"+slug, viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
	})
}

// TestE2E_ScannerCatalog pins the scanner capability contract: the
// authenticated catalog is the deterministic registration-order list of
// built-in parsers with their versions and capabilities. Any signed-in user
// may read it; project keys and anonymous callers are refused.
func TestE2E_ScannerCatalog(t *testing.T) {
	t.Run("admin sees the full deterministic catalog", func(t *testing.T) {
		descs := request[[]scannerDescriptor](t, http.MethodGet, "/api/v1/scanners", adminToken, nil, http.StatusOK)
		names := make([]string, 0, len(descs))
		for _, d := range descs {
			names = append(names, d.Name)
			require.NotEmpty(t, d.Version, "scanner %q must publish its version", d.Name)
		}
		require.Equal(t, []string{
			"trivy", "osv-scanner", "semgrep", "checkov", "dependency-check",
			"grype", "sbom", "sarif", "gitleaks", "tfsec", "nuclei",
		}, names, "the catalog is the built-in registry in registration order")

		byName := map[string]scannerDescriptor{}
		for _, d := range descs {
			byName[d.Name] = d
		}
		require.True(t, byName["trivy"].ProvidesPackages,
			"package producers are part of the capability contract (watcher inventory depends on it)")
		require.Contains(t, byName["sarif"].FindingKinds, "sast")
	})

	t.Run("non-admin session users read the catalog", func(t *testing.T) {
		viewerToken := login(t, "e2e-viewer@example.com", adminPass)

		descs := request[[]scannerDescriptor](t, http.MethodGet, "/api/v1/scanners", viewerToken, nil, http.StatusOK)
		require.NotEmpty(t, descs)
	})

	t.Run("project keys and anonymous callers are refused", func(t *testing.T) {
		key := mintKey(t, newProject(t, "org-scan-key"))
		status, raw := doJSON(t, http.MethodGet, "/api/v1/scanners", key, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_role", errorCode(t, raw),
			"project keys never hold session roles")

		status, raw = doJSON(t, http.MethodGet, "/api/v1/scanners", "", nil)
		require.Equal(t, http.StatusUnauthorized, status)
		require.Equal(t, "missing_token", errorCode(t, raw))
	})
}
