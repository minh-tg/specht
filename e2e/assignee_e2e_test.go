//go:build e2e

package e2e

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestE2E_FindingAssignee pins who can own a finding and what the list shows.
func TestE2E_FindingAssignee(t *testing.T) {
	slug := newProject(t, "assignee")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high.sarif.json")
	finding := highFinding(t, slug)
	path := "/api/v1/findings/" + finding.ID + "/assignee"

	admin := request[userProfile](t, http.MethodGet, "/api/v1/me", adminToken, nil, http.StatusOK)

	type answer struct {
		Assignee *struct {
			UserID string `json:"user_id"`
			Name   string `json:"name"`
		} `json:"assignee"`
	}
	got := request[answer](t, http.MethodPut, path, adminToken, map[string]string{"user_id": admin.ID}, http.StatusOK)
	require.NotNil(t, got.Assignee)
	require.Equal(t, admin.ID, got.Assignee.UserID)
	require.NotEmpty(t, got.Assignee.Name)

	mine := request[[]findingResponse](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/findings?assignee=me", adminToken, nil, http.StatusOK)
	require.Len(t, mine, 1)

	status, raw := doJSON(t, http.MethodPut, path, adminToken, map[string]string{"user_id": "not-a-uuid"})
	require.Equal(t, http.StatusBadRequest, status, string(raw))
	status, raw = doJSON(t, http.MethodPut, path, adminToken,
		map[string]string{"user_id": "00000000-0000-0000-0000-000000000000"})
	require.Equal(t, http.StatusBadRequest, status, string(raw))
	require.Equal(t, "assignee_not_member", errorCode(t, raw))

	cleared := request[answer](t, http.MethodPut, path, adminToken, map[string]string{"user_id": ""}, http.StatusOK)
	require.Nil(t, cleared.Assignee)
	none := request[[]findingResponse](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/findings?assignee=me", adminToken, nil, http.StatusOK)
	require.Empty(t, none)

	t.Run("a member can take what nobody owns, and nothing else", func(t *testing.T) {
		session := request[authResponse](t, http.MethodPost, "/api/v1/auth/login", "",
			map[string]string{"email": "e2e-viewer@example.com", "password": adminPass}, http.StatusOK)
		member := request[userProfile](t, http.MethodGet, "/api/v1/me", session.Token, nil, http.StatusOK)
		azAddMember(t, slug, member.ID, "member")
		mustAssign := func(token, userID string, want int) {
			t.Helper()
			status, raw := doJSON(t, http.MethodPut, path, token, map[string]string{"user_id": userID})
			require.Equal(t, want, status, string(raw))
		}

		mustAssign(session.Token, admin.ID, http.StatusForbidden) // cannot assign someone else
		mustAssign(session.Token, member.ID, http.StatusOK)       // takes what nobody owns
		mustAssign(session.Token, "", http.StatusOK)              // lets go of their own

		mustAssign(adminToken, admin.ID, http.StatusOK)
		mustAssign(session.Token, member.ID, http.StatusForbidden) // cannot take someone else's
		mustAssign(session.Token, "", http.StatusForbidden)        // cannot clear someone else's
		mustAssign(adminToken, member.ID, http.StatusOK)           // a manager can
	})

	t.Run("assignee=me with a key matches nothing", func(t *testing.T) {
		mine := request[[]findingResponse](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/findings?assignee=me", key, nil, http.StatusOK)
		require.Empty(t, mine)
	})
}
