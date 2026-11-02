//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type projectDefaultBranch struct {
	Slug          string  `json:"slug"`
	DefaultBranch *string `json:"default_branch"`
}

// TestE2E_DefaultBranchMakesAFormerPullRequestHeadABaseline pins the project
// default branch. main was once the head of a pull request, so without the
// setting main is a change branch: its reports are no baseline and no trunk
// has main's own high, so a pull request counts it as introduced too. Once a
// project admin names main as the default branch, main is the baseline again:
// its high is pre-existing and only the finding main never had is introduced.
func TestE2E_DefaultBranchMakesAFormerPullRequestHeadABaseline(t *testing.T) {
	slug := newProject(t, "default-branch")
	key := mintKey(t, slug)

	carryPush(t, slug, key, "high.sarif.json", "main", "f200000000000000000000000000000000000001", "")
	// main was the head of a pull request into a release branch once.
	carryPush(t, slug, key, "high.sarif.json", "main", "f200000000000000000000000000000000000002", "release/1")
	// Another branch has E2E-NEW-003 and is blocked on it.
	other := carryPush(t, slug, key, "high-new.sarif.json", "feat/other", "f200000000000000000000000000000000000003", "main")
	require.Equal(t, 2, other.IntroducedCount, "main is no trunk without the setting")

	unset := carryPush(t, slug, key, "high-new.sarif.json", "feat/x", "f200000000000000000000000000000000000004", "main")
	require.Equal(t, 2, unset.IntroducedCount,
		"without the setting main is a change branch, so nothing is trunk debt")

	got := request[projectDefaultBranch](t, http.MethodGet, "/api/v1/projects/"+slug, adminToken, nil, http.StatusOK)
	require.Nil(t, got.DefaultBranch)
	set := request[projectDefaultBranch](t, http.MethodPut, "/api/v1/projects/"+slug, adminToken,
		map[string]any{"default_branch": " main "}, http.StatusOK)
	require.NotNil(t, set.DefaultBranch)
	require.Equal(t, "main", *set.DefaultBranch)

	after := carryPush(t, slug, key, "high-new.sarif.json", "feat/y", "f200000000000000000000000000000000000005", "main")
	require.Equal(t, 1, after.IntroducedCount, "main is the baseline again and never had E2E-NEW-003")
	require.Equal(t, 1, after.PreExistingCount, "main's own high is pre-existing")
	require.True(t, after.ThresholdBreached)

	// Another change branch stays refused with the setting in place.
	viaOther := carryPush(t, slug, key, "high-new.sarif.json", "feat/z", "f200000000000000000000000000000000000006", "feat/other")
	require.Equal(t, 1, viaOther.IntroducedCount,
		"feat/other is no baseline; main still has the high, and E2E-NEW-003 stays introduced")
	require.Equal(t, 1, viaOther.PreExistingCount)

	cleared := request[projectDefaultBranch](t, http.MethodPut, "/api/v1/projects/"+slug, adminToken,
		map[string]any{"default_branch": ""}, http.StatusOK)
	require.Nil(t, cleared.DefaultBranch)
}

// TestE2E_DefaultBranchRefusesAStandInBaseline pins that, once the project
// names its default branch, an ingest key cannot upload a report of the
// branch's blockers somewhere else and name it as the base: a report without
// a branch and a report on a fresh branch name are no baselines, so the
// finding the branch introduced on its first push stays introduced.
func TestE2E_DefaultBranchRefusesAStandInBaseline(t *testing.T) {
	slug := newProject(t, "default-branch-stand-in")
	key := mintKey(t, slug)
	request[projectDefaultBranch](t, http.MethodPut, "/api/v1/projects/"+slug, adminToken,
		map[string]any{"default_branch": "main"}, http.StatusOK)
	carryPush(t, slug, key, "high.sarif.json", "main", "f300000000000000000000000000000000000001", "")

	first := carryPush(t, slug, key, "high-new.sarif.json", "feat/x", "f300000000000000000000000000000000000002", "main")
	require.Equal(t, 1, first.IntroducedCount, "E2E-NEW-003 is new against main")

	// The stand-ins hold both findings.
	request[ingestResponse](t, http.MethodPost, "/api/v1/reports", key,
		ingestBodyWith(t, slug, "high-new.sarif.json", map[string]any{
			"commit_sha": "f300000000000000000000000000000000000003",
		}), http.StatusCreated)
	carryPush(t, slug, key, "high-new.sarif.json", "attacker-trunk", "f300000000000000000000000000000000000004", "")

	pushes := map[string]string{
		"f300000000000000000000000000000000000003": "f300000000000000000000000000000000000005",
		"attacker-trunk": "f300000000000000000000000000000000000006",
	}
	for base, commit := range pushes {
		pushed := carryPush(t, slug, key, "high-new.sarif.json", "feat/x", commit, base)
		require.Equalf(t, 1, pushed.IntroducedCount, "base %s must not vouch for the branch's finding", base)
		require.True(t, pushed.ThresholdBreached)
	}
}

// TestE2E_DefaultBranchNeedsAProjectAdmin pins who may set the default branch:
// a global admin or an admin of the project. A project member and an API key
// are refused, and an invalid value is a 400.
func TestE2E_DefaultBranchNeedsAProjectAdmin(t *testing.T) {
	slug := newProject(t, "default-branch-authz")
	key := mintKey(t, slug)
	viewerToken := login(t, "e2e-viewer@example.com", adminPass)
	viewerMe := request[userProfile](t, http.MethodGet, "/api/v1/me", viewerToken, nil, http.StatusOK)
	request[memberResponse](t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
		map[string]string{"user_id": viewerMe.ID, "role": "member"}, http.StatusCreated)

	status, _ := doJSON(t, http.MethodPut, "/api/v1/projects/"+slug, viewerToken,
		map[string]any{"default_branch": "main"})
	require.Equal(t, http.StatusForbidden, status, "a project member may not set it")

	status, _ = doJSON(t, http.MethodPut, "/api/v1/projects/"+slug, key,
		map[string]any{"default_branch": "main"})
	require.Contains(t, []int{http.StatusUnauthorized, http.StatusForbidden}, status, "an API key may not set it")

	got := request[projectDefaultBranch](t, http.MethodGet, "/api/v1/projects/"+slug, adminToken, nil, http.StatusOK)
	require.Nil(t, got.DefaultBranch, "nothing was written")

	status, raw := doJSON(t, http.MethodPut, "/api/v1/projects/"+slug, adminToken,
		map[string]any{"default_branch": strings.Repeat("b", 256)})
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_field", errorCode(t, raw))

	request[memberResponse](t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
		map[string]string{"user_id": viewerMe.ID, "role": "admin"}, http.StatusCreated)
	set := request[projectDefaultBranch](t, http.MethodPut, "/api/v1/projects/"+slug, viewerToken,
		map[string]any{"default_branch": "main"}, http.StatusOK)
	require.Equal(t, "main", *set.DefaultBranch, "a project admin may set it")
}
