//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestE2E_WaiverLifecycleAndExpirySweep covers the waiver business process:
// a scoped waiver silences a blocking finding at the gate, toggling it
// restores the block, deleting removes it — and a time-limited waiver is
// auto-disabled by the sweeper with an audit event and a re-blocked gate.
func TestE2E_WaiverLifecycleAndExpirySweep(t *testing.T) {
	slug := newProject(t, "waiver")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high-medium.sarif.json")
	target := highFinding(t, slug)

	waiver := createWaiver(t, slug, "release-window", target.ID, "")
	require.True(t, waiver.Enabled)

	// The create response is a summary; children (targets) come back on
	// the detail read, per the public representation contract.
	detail := request[waiverDetail](t, http.MethodGet,
		"/api/v1/projects/"+slug+"/waivers/"+waiver.ID, adminToken, nil, http.StatusOK)
	require.Len(t, detail.Targets, 1)
	require.Equal(t, target.ID, detail.Targets[0].FindingID)

	t.Run("active waiver silences the gate", func(t *testing.T) {
		gs := getGate(t, slug, "")
		require.False(t, gs.ThresholdBreached)
		require.EqualValues(t, 1, gs.WaivedCount)
		require.Zero(t, gs.BlockingCount)

		matched := request[checkMatchResponse](t, http.MethodPost,
			"/api/v1/projects/"+slug+"/waivers/check-match", adminToken,
			map[string]string{"finding_id": target.ID}, http.StatusOK)
		require.True(t, matched.Matched)
	})

	t.Run("disabling the waiver restores the block", func(t *testing.T) {
		toggled := request[waiverDetail](t, http.MethodPost,
			"/api/v1/projects/"+slug+"/waivers/"+waiver.ID+"/toggle", adminToken, nil, http.StatusOK)
		require.False(t, toggled.Enabled)

		gs := getGate(t, slug, "")
		require.True(t, gs.ThresholdBreached, "a disabled waiver must stop silencing")

		matched := request[checkMatchResponse](t, http.MethodPost,
			"/api/v1/projects/"+slug+"/waivers/check-match", adminToken,
			map[string]string{"finding_id": target.ID}, http.StatusOK)
		require.False(t, matched.Matched)
	})

	t.Run("re-enabling restores the waiver and its audit trail", func(t *testing.T) {
		enabled := request[waiverDetail](t, http.MethodPost,
			"/api/v1/projects/"+slug+"/waivers/"+waiver.ID+"/toggle", adminToken, nil, http.StatusOK)
		require.True(t, enabled.Enabled)

		gs := getGate(t, slug, "")
		require.False(t, gs.ThresholdBreached)

		events := request[[]waiverEvent](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/waivers/"+waiver.ID+"/events", adminToken, nil, http.StatusOK)
		types := make([]string, 0, len(events))
		for _, e := range events {
			types = append(types, e.EventType)
		}
		require.Contains(t, types, "created")
		require.Contains(t, types, "disabled")
		require.Contains(t, types, "enabled")
	})

	t.Run("updating the waiver sets, keeps, and clears its expiry", func(t *testing.T) {
		waiverPath := "/api/v1/projects/" + slug + "/waivers/" + waiver.ID
		expiresAt := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)

		// A PUT can introduce an expiry where none existed.
		updated := request[waiverDetail](t, http.MethodPut, waiverPath, adminToken,
			map[string]any{"name": "release-window", "expires_at": expiresAt}, http.StatusOK)
		require.NotNil(t, updated.ExpiresAt, "PUT sets expires_at")
		sent, err := time.Parse(time.RFC3339, expiresAt)
		require.NoError(t, err)
		got, err := time.Parse(time.RFC3339, *updated.ExpiresAt)
		require.NoError(t, err)
		require.True(t, sent.Equal(got), "want %s got %s", expiresAt, *updated.ExpiresAt)

		// Omitting the field leaves the stored expiry untouched.
		kept := request[waiverDetail](t, http.MethodPut, waiverPath, adminToken,
			map[string]any{"name": "release-window-renamed"}, http.StatusOK)
		require.NotNil(t, kept.ExpiresAt, "omitting expires_at keeps the stored value")
		require.Equal(t, *updated.ExpiresAt, *kept.ExpiresAt)

		// A malformed timestamp never reaches the store.
		status, raw := doJSON(t, http.MethodPut, waiverPath, adminToken,
			map[string]any{"name": "x", "expires_at": "soon"})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "invalid_expires_at", errorCode(t, raw))

		// The empty string clears the expiry.
		cleared := request[waiverDetail](t, http.MethodPut, waiverPath, adminToken,
			map[string]any{"expires_at": ""}, http.StatusOK)
		require.Nil(t, cleared.ExpiresAt, "the empty string clears the expiry")

		// Throughout, the waiver keeps silencing the gate.
		require.False(t, getGate(t, slug, "").ThresholdBreached)
	})

	t.Run("deleting the waiver removes it", func(t *testing.T) {
		status, _ := doJSON(t, http.MethodDelete,
			"/api/v1/projects/"+slug+"/waivers/"+waiver.ID, adminToken, nil)
		require.Equal(t, http.StatusNoContent, status)

		status, _ = doJSON(t, http.MethodGet,
			"/api/v1/projects/"+slug+"/waivers/"+waiver.ID, adminToken, nil)
		require.Equal(t, http.StatusNotFound, status)

		gs := getGate(t, slug, "")
		require.True(t, gs.ThresholdBreached, "gate must block once no waiver remains")
	})

	t.Run("time-limited waiver is auto-disabled by the sweeper", func(t *testing.T) {
		expiresAt := time.Now().Add(5 * time.Second).UTC().Format(time.RFC3339Nano)
		limited := createWaiver(t, slug, "short-window", target.ID, expiresAt)

		gs := getGate(t, slug, "")
		require.False(t, gs.ThresholdBreached, "the time-limited waiver must apply immediately")

		// The waiver must be visible with its expiry over the API.
		fetched := request[waiverDetail](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/waivers/"+limited.ID, adminToken, nil, http.StatusOK)
		require.NotNil(t, fetched.ExpiresAt, "expires_at must round-trip through the API")

		eventually(t, 30*time.Second, "sweeper must disable the expired waiver", func() bool {
			got := request[waiverDetail](t, http.MethodGet,
				"/api/v1/projects/"+slug+"/waivers/"+limited.ID, adminToken, nil, http.StatusOK)
			return !got.Enabled
		})

		events := request[[]waiverEvent](t, http.MethodGet,
			"/api/v1/projects/"+slug+"/waivers/"+limited.ID+"/events", adminToken, nil, http.StatusOK)
		var autoDisabled *waiverEvent
		for i := range events {
			if events[i].EventType == "auto_disabled" {
				autoDisabled = &events[i]
			}
		}
		require.NotNil(t, autoDisabled, "expiry must produce an auto_disabled audit event")
		var meta map[string]string
		require.NoError(t, json.Unmarshal(autoDisabled.Metadata, &meta))
		require.Equal(t, "waiver_expired", meta["reason"])
		require.Equal(t, "short-window", meta["waiver_name"])

		gs = getGate(t, slug, "")
		require.True(t, gs.ThresholdBreached, "gate must re-block once the waiver expires")
		require.EqualValues(t, 1, gs.BlockingCount)

		matched := request[checkMatchResponse](t, http.MethodPost,
			"/api/v1/projects/"+slug+"/waivers/check-match", adminToken,
			map[string]string{"finding_id": target.ID}, http.StatusOK)
		require.False(t, matched.Matched, "an expired waiver must not match")
	})
}

type waiverReview struct {
	ID           string  `json:"id"`
	Status       string  `json:"status"`
	Reason       string  `json:"reason"`
	ScopeAll     bool    `json:"scope_all"`
	RequestedBy  *string `json:"requested_by"`
	DecidedBy    *string `json:"decided_by"`
	DecisionNote string  `json:"decision_note"`
}

// TestE2E_WaiverRequestApproval covers the review lifecycle: a member asks
// for a waiver, the gate stays blocked until a manager or admin approves it,
// and rejected or withdrawn requests never silence anything.
func TestE2E_WaiverRequestApproval(t *testing.T) {
	slug := newProject(t, "waiver-review")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high-medium.sarif.json")
	target := highFinding(t, slug)

	memberToken := login(t, "e2e-viewer@example.com", adminPass)
	memberMe := request[userProfile](t, http.MethodGet, "/api/v1/me", memberToken, nil, http.StatusOK)
	status, raw := doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
		map[string]string{"user_id": memberMe.ID, "role": "member"})
	require.Contains(t, []int{http.StatusOK, http.StatusCreated}, status, string(raw))

	base := "/api/v1/projects/" + slug + "/waivers"
	expires := time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339)
	requestBody := func(findingID string) map[string]any {
		return map[string]any{"target_ids": []string{findingID}, "reason": "not reachable from the public API", "expires_at": expires}
	}

	var pending waiverReview
	t.Run("a member's request stays pending and the gate stays blocked", func(t *testing.T) {
		pending = request[waiverReview](t, http.MethodPost, base+"/requests", memberToken, requestBody(target.ID), http.StatusCreated)
		require.Equal(t, "pending", pending.Status)
		require.Equal(t, "not reachable from the public API", pending.Reason)
		require.NotNil(t, pending.RequestedBy)
		require.Equal(t, memberMe.ID, *pending.RequestedBy)

		require.True(t, getGate(t, slug, "").ThresholdBreached, "a pending request must not silence the gate")
		matched := request[checkMatchResponse](t, http.MethodPost, base+"/check-match", adminToken,
			map[string]string{"finding_id": target.ID}, http.StatusOK)
		require.False(t, matched.Matched)

		status, raw := doJSON(t, http.MethodPost, base+"/requests", memberToken, requestBody(target.ID))
		require.Equal(t, http.StatusConflict, status, string(raw))
		require.Equal(t, "waiver_request_exists", errorCode(t, raw))
	})

	t.Run("a member cannot decide, create or manage waivers", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, base+"/"+pending.ID+"/approve", memberToken, map[string]string{})
		require.Equal(t, http.StatusForbidden, status, string(raw))
		status, _ = doJSON(t, http.MethodPost, base, memberToken,
			map[string]any{"name": "mine", "target_ids": []string{target.ID}})
		require.Equal(t, http.StatusForbidden, status)
		require.True(t, getGate(t, slug, "").ThresholdBreached)
	})

	t.Run("requests are validated", func(t *testing.T) {
		for name, body := range map[string]map[string]any{
			"no reason": {"target_ids": []string{target.ID}, "expires_at": expires},
			"no expiry": {"target_ids": []string{target.ID}, "reason": "x"},
			"no target": {"reason": "x", "expires_at": expires},
		} {
			status, raw := doJSON(t, http.MethodPost, base+"/requests", memberToken, body)
			require.Equal(t, http.StatusBadRequest, status, name+": "+string(raw))
		}
	})

	t.Run("the list shows the request and filters by status", func(t *testing.T) {
		got := request[[]waiverReview](t, http.MethodGet, base+"?status=pending", memberToken, nil, http.StatusOK)
		require.Len(t, got, 1)
		require.Equal(t, pending.ID, got[0].ID)
		got = request[[]waiverReview](t, http.MethodGet, base+"?status=approved", memberToken, nil, http.StatusOK)
		require.Empty(t, got)
		status, raw := doJSON(t, http.MethodGet, base+"?status=bogus", memberToken, nil)
		require.Equal(t, http.StatusBadRequest, status, string(raw))
	})

	t.Run("approval silences the gate and cannot be repeated", func(t *testing.T) {
		approved := request[waiverReview](t, http.MethodPost, base+"/"+pending.ID+"/approve", adminToken,
			map[string]string{"note": "agreed"}, http.StatusOK)
		require.Equal(t, "approved", approved.Status)
		require.Equal(t, "agreed", approved.DecisionNote)
		require.NotNil(t, approved.DecidedBy)

		gs := getGate(t, slug, "")
		require.False(t, gs.ThresholdBreached)
		require.EqualValues(t, 1, gs.WaivedCount)

		status, raw := doJSON(t, http.MethodPost, base+"/"+pending.ID+"/approve", adminToken, map[string]string{})
		require.Equal(t, http.StatusConflict, status, string(raw))
		require.Equal(t, "waiver_not_pending", errorCode(t, raw))

		events := request[[]waiverEvent](t, http.MethodGet, base+"/"+pending.ID+"/events", adminToken, nil, http.StatusOK)
		types := make([]string, 0, len(events))
		for _, e := range events {
			types = append(types, e.EventType)
		}
		require.Contains(t, types, "requested")
		require.Contains(t, types, "approved")
	})

	t.Run("a rejection needs a note and a withdrawn request never counts", func(t *testing.T) {
		var other findingResponse
		for _, f := range listFindings(t, slug) {
			if f.ID != target.ID {
				other = f
				break
			}
		}
		require.NotEmpty(t, other.ID)

		second := request[waiverReview](t, http.MethodPost, base+"/requests", memberToken, requestBody(other.ID), http.StatusCreated)
		status, raw := doJSON(t, http.MethodPost, base+"/"+second.ID+"/reject", adminToken, map[string]string{})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		rejected := request[waiverReview](t, http.MethodPost, base+"/"+second.ID+"/reject", adminToken,
			map[string]string{"note": "fix the dependency instead"}, http.StatusOK)
		require.Equal(t, "rejected", rejected.Status)
		require.Equal(t, "fix the dependency instead", rejected.DecisionNote)

		third := request[waiverReview](t, http.MethodPost, base+"/requests", memberToken, requestBody(other.ID), http.StatusCreated)
		status, raw = doJSON(t, http.MethodPost, base+"/"+third.ID+"/withdraw", adminToken, nil)
		require.Equal(t, http.StatusForbidden, status, "only the requester withdraws: "+string(raw))
		withdrawn := request[waiverReview](t, http.MethodPost, base+"/"+third.ID+"/withdraw", memberToken, nil, http.StatusOK)
		require.Equal(t, "withdrawn", withdrawn.Status)

		matched := request[checkMatchResponse](t, http.MethodPost, base+"/check-match", adminToken,
			map[string]string{"finding_id": other.ID}, http.StatusOK)
		require.False(t, matched.Matched, "rejected and withdrawn requests silence nothing")
	})

	t.Run("a waiver must say what it covers", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, base, adminToken, map[string]any{"name": "everything"})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "waiver_scope_required", errorCode(t, raw))

		all := request[waiverReview](t, http.MethodPost, base, adminToken,
			map[string]any{"name": "everything", "scope": "all"}, http.StatusCreated)
		require.True(t, all.ScopeAll)
		require.Equal(t, "approved", all.Status)
	})
}
