//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestE2E_SoleManagerApprovesOwnWaiver covers a project whose only person with
// manager rights asks for a waiver. Nobody else can decide it, so they may
// approve it themselves with a note, and the approval is marked self-approved.
// Once a second manager reaches the project, directly or through a team, the
// two-person rule is back.
func TestE2E_SoleManagerApprovesOwnWaiver(t *testing.T) {
	slug := newProject(t, "sole-manager")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high.sarif.json")
	finding := highFinding(t, slug)
	base := "/api/v1/projects/" + slug

	// The owner becomes the project's admin and the suite admin, who created
	// it, leaves. A global admin who is not on the project does not count, and
	// neither does a plain member.
	owner := azRegister(t, "sole-owner")
	azAddMember(t, slug, owner.UserID, "admin")
	suiteAdmin := request[userProfile](t, http.MethodGet, "/api/v1/me", adminToken, nil, http.StatusOK)
	status, raw := doJSON(t, http.MethodDelete, base+"/members/"+suiteAdmin.ID, adminToken, nil)
	require.Equal(t, http.StatusNoContent, status, string(raw))
	member := azRegister(t, "sole-member")
	azAddMember(t, slug, member.UserID, "member")

	selfApprove := func() bool {
		t.Helper()
		p := request[struct {
			Permissions struct {
				ApproveWaivers     bool `json:"approve_waivers"`
				SelfApproveWaivers bool `json:"self_approve_waivers"`
			} `json:"permissions"`
		}](t, http.MethodGet, base, owner.Token, nil, http.StatusOK)
		require.True(t, p.Permissions.ApproveWaivers)
		return p.Permissions.SelfApproveWaivers
	}
	ask := func() string {
		t.Helper()
		w := request[waiverDetail](t, http.MethodPost, base+"/waivers/requests", owner.Token, map[string]any{
			"target_ids": []string{finding.ID},
			"reason":     "Only reachable from the admin network.",
			"expires_at": time.Now().Add(7 * 24 * time.Hour).UTC().Format(time.RFC3339),
		}, http.StatusCreated)
		return w.ID
	}
	approve := func(token, id, note string) (int, []byte) {
		t.Helper()
		return doJSON(t, http.MethodPost, base+"/waivers/"+id+"/approve", token, map[string]string{"note": note})
	}

	t.Run("the only manager approves their own request with a note", func(t *testing.T) {
		require.True(t, selfApprove())
		id := ask()

		status, raw := approve(owner.Token, id, "  ")
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "invalid_body", errorCode(t, raw))
		require.Contains(t, string(raw), "a note is required")

		status, raw = approve(owner.Token, id, "Nobody else manages this project.")
		require.Equal(t, http.StatusOK, status, string(raw))

		events := request[[]waiverEvent](t, http.MethodGet, base+"/waivers/"+id+"/events", owner.Token, nil, http.StatusOK)
		var approved *waiverEvent
		for i := range events {
			if events[i].EventType == "approved" {
				approved = &events[i]
			}
		}
		require.NotNil(t, approved, "an approved event is recorded")
		var meta struct {
			Note         string `json:"note"`
			SelfApproved bool   `json:"self_approved"`
		}
		require.NoError(t, json.Unmarshal(approved.Metadata, &meta))
		require.True(t, meta.SelfApproved)
		require.Equal(t, "Nobody else manages this project.", meta.Note)

		gs := getGate(t, slug, "")
		require.EqualValues(t, 1, gs.WaivedCount, "the approved waiver counts in the gate")
	})

	t.Run("a manager through a team is someone else who can decide", func(t *testing.T) {
		reviewer := azRegister(t, "sole-team-reviewer")
		team := request[struct {
			ID string `json:"id"`
		}](t, http.MethodPost, "/api/v1/teams", adminToken,
			map[string]string{"name": "sole-reviewers-" + randomHex(4)}, http.StatusCreated)
		azAddTeamMember(t, team.ID, reviewer.UserID, "member")
		azSetTeamLink(t, slug, team.ID, "manager")
		defer azUnlinkTeam(t, slug, team.ID)

		require.False(t, selfApprove())
		id := ask()
		status, raw := approve(owner.Token, id, "Nobody else manages this project.")
		require.Equal(t, http.StatusForbidden, status, string(raw))
		require.Equal(t, "self_approval", errorCode(t, raw))

		status, raw = approve(reviewer.Token, id, "")
		require.Equal(t, http.StatusOK, status, string(raw))
	})

	t.Run("a second direct manager is someone else who can decide", func(t *testing.T) {
		second := azRegister(t, "sole-second")
		azAddMember(t, slug, second.UserID, "manager")

		require.False(t, selfApprove())
		id := ask()
		status, raw := approve(owner.Token, id, "Nobody else manages this project.")
		require.Equal(t, http.StatusForbidden, status, string(raw))
		require.Equal(t, "self_approval", errorCode(t, raw))
	})
}
