//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type needsYouItem struct {
	Kind        string `json:"kind"`
	ProjectSlug string `json:"project_slug"`
	Title       string `json:"title"`
	Status      string `json:"status"`
	Detail      string `json:"detail"`
	Link        string `json:"link"`
}

type needsYouList struct {
	Count            int            `json:"count"`
	AssignedFindings int            `json:"assigned_findings"`
	Items            []needsYouItem `json:"items"`
}

func needsYouOf(t *testing.T, token string) needsYouList {
	t.Helper()
	return request[needsYouList](t, http.MethodGet, "/api/v1/me/needs-you", token, nil, http.StatusOK)
}

func (l needsYouList) ofKind(kind, slug string) []needsYouItem {
	var out []needsYouItem
	for _, item := range l.Items {
		if item.Kind == kind && item.ProjectSlug == slug {
			out = append(out, item)
		}
	}
	return out
}

// TestE2E_NeedsYou follows one waiver request through the page of each person it touches: the
// manager sees it waiting, the member who asked sees the answer, and an assigned finding shows
// for its assignee. A person outside the project sees none of it.
func TestE2E_NeedsYou(t *testing.T) {
	slug := newProject(t, "needs-you")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high.sarif.json")
	finding := highFinding(t, slug)
	base := "/api/v1/projects/" + slug

	manager := azRegister(t, "ny-manager")
	azAddMember(t, slug, manager.UserID, "manager")
	member := azRegister(t, "ny-member")
	azAddMember(t, slug, member.UserID, "member")
	outsider := azRegister(t, "ny-outsider")

	t.Run("nothing waits on a person who has no work", func(t *testing.T) {
		got := needsYouOf(t, outsider.Token)
		require.Zero(t, got.Count)
		require.NotNil(t, got.Items, "an empty list is [], not null")
		require.Empty(t, got.Items)
	})

	var waiverID string
	t.Run("a request waits on the manager, and not on the member who asked", func(t *testing.T) {
		w := request[waiverDetail](t, http.MethodPost, base+"/waivers/requests", member.Token, map[string]any{
			"target_ids": []string{finding.ID},
			"reason":     "Only reachable from the admin network.",
			"expires_at": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		}, http.StatusCreated)
		waiverID = w.ID

		waiting := needsYouOf(t, manager.Token).ofKind("waiver_to_decide", slug)
		require.Len(t, waiting, 1)
		require.Equal(t, "Only reachable from the admin network.", waiting[0].Detail)
		require.Equal(t, "/"+slug+"/waivers", waiting[0].Link)
		require.NotZero(t, needsYouOf(t, manager.Token).Count)

		require.Empty(t, needsYouOf(t, member.Token).ofKind("waiver_to_decide", slug),
			"the person who asked waits on the manager")
		require.Empty(t, needsYouOf(t, outsider.Token).Items, "a project the person cannot reach never shows")
	})

	t.Run("the answer reaches the member and the request leaves the manager's list", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, base+"/waivers/"+waiverID+"/approve", manager.Token,
			map[string]string{"note": "Fine until the VPN change."})
		require.Equal(t, http.StatusOK, status, string(raw))

		require.Empty(t, needsYouOf(t, manager.Token).ofKind("waiver_to_decide", slug))
		answers := needsYouOf(t, member.Token).ofKind("request_decided", slug)
		require.Len(t, answers, 1)
		require.Equal(t, "approved", answers[0].Status)
		require.Equal(t, "Fine until the VPN change.", answers[0].Detail)
		require.NotZero(t, needsYouOf(t, member.Token).Count, "a fresh answer shows in the badge")
	})

	t.Run("a rejected request carries the reviewer's note", func(t *testing.T) {
		second := request[waiverDetail](t, http.MethodPost, base+"/waivers/requests", member.Token, map[string]any{
			"target_ids": []string{finding.ID},
			"reason":     "Again.",
			"expires_at": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		}, http.StatusCreated)
		status, raw := doJSON(t, http.MethodPost, base+"/waivers/"+second.ID+"/reject", manager.Token,
			map[string]string{"note": "Too broad."})
		require.Equal(t, http.StatusOK, status, string(raw))

		var rejected []needsYouItem
		for _, item := range needsYouOf(t, member.Token).ofKind("request_decided", slug) {
			if item.Status == "rejected" {
				rejected = append(rejected, item)
			}
		}
		require.Len(t, rejected, 1)
		require.Equal(t, "Too broad.", rejected[0].Detail)
	})

	t.Run("an approved waiver that ends within a week waits on the manager", func(t *testing.T) {
		ending := needsYouOf(t, manager.Token).ofKind("waiver_ending", slug)
		require.Len(t, ending, 1, "the approved waiver ends in seven days")
		require.Empty(t, needsYouOf(t, member.Token).ofKind("waiver_ending", slug), "a member does not manage it")
	})

	t.Run("an assigned finding waits on its assignee", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPut, "/api/v1/findings/"+finding.ID+"/assignee", manager.Token,
			map[string]string{"user_id": member.UserID})
		require.Equal(t, http.StatusOK, status, string(raw))

		got := needsYouOf(t, member.Token)
		assigned := got.ofKind("finding_assigned", slug)
		require.Len(t, assigned, 1)
		require.Equal(t, "/"+slug+"/findings/"+finding.ID, assigned[0].Link)
		require.GreaterOrEqual(t, got.AssignedFindings, 1)
		require.Empty(t, needsYouOf(t, manager.Token).ofKind("finding_assigned", slug), "it is the member's, not the manager's")
	})

	t.Run("a project key has no person behind it", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodGet, "/api/v1/me/needs-you", key, nil)
		require.Equal(t, http.StatusForbidden, status, string(raw))
	})
}

// TestE2E_NeedsYouGlobalAdminOwnRequest: a global admin may approve their own waiver request even
// when a project manager could decide it too, so the request waits on them as well.
func TestE2E_NeedsYouGlobalAdminOwnRequest(t *testing.T) {
	slug := newProject(t, "needs-you-admin")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high.sarif.json")
	finding := highFinding(t, slug)
	base := "/api/v1/projects/" + slug

	manager := azRegister(t, "ny-admin-manager")
	azAddMember(t, slug, manager.UserID, "manager")

	request[waiverDetail](t, http.MethodPost, base+"/waivers/requests", adminToken, map[string]any{
		"target_ids": []string{finding.ID},
		"reason":     "Admin's own request.",
		"expires_at": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}, http.StatusCreated)

	waiting := needsYouOf(t, adminToken).ofKind("waiver_to_decide", slug)
	require.Len(t, waiting, 1, "the admin may approve it, so it waits on them")
	require.Equal(t, "Admin's own request.", waiting[0].Detail)
	require.Len(t, needsYouOf(t, manager.Token).ofKind("waiver_to_decide", slug), 1)
}
