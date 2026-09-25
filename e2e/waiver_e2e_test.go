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
