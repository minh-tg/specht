//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

type switchedWaiver struct {
	ID        string  `json:"id"`
	Enabled   bool    `json:"enabled"`
	Status    string  `json:"status"`
	ExpiresAt *string `json:"expires_at,omitempty"`
	UpdatedAt string  `json:"updated_at"`
}

type switchEvent struct {
	EventType string `json:"event_type"`
	ActorID   string `json:"actor_id"`
}

func waiverEventTypes(t *testing.T, base, id string) []string {
	t.Helper()
	events := request[[]switchEvent](t, http.MethodGet, base+"/"+id+"/events", adminToken, nil, http.StatusOK)
	// The API lists the newest event first.
	types := make([]string, 0, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		types = append(types, events[i].EventType)
	}
	return types
}

// TestE2E_WaiverRevokeAndRestore covers putting a revoked waiver back in force:
// the gate follows each switch, a repeated call is harmless, a stale Undo cannot
// override a newer change, an expired waiver stays off, and only a project
// manager may switch a waiver.
func TestE2E_WaiverRevokeAndRestore(t *testing.T) {
	slug := newProject(t, "waiver-restore")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high-medium.sarif.json")
	target := highFinding(t, slug)
	base := "/api/v1/projects/" + slug + "/waivers"
	admin := request[profileEnvelope](t, http.MethodGet, "/api/v1/me", adminToken, nil, http.StatusOK)

	waiver := createWaiver(t, slug, "release-window", target.ID, "")
	require.True(t, waiver.Enabled)
	require.False(t, getGate(t, slug, "").ThresholdBreached)

	var revoked switchedWaiver
	t.Run("revoking the waiver blocks the gate again", func(t *testing.T) {
		revoked = request[switchedWaiver](t, http.MethodPost, base+"/"+waiver.ID+"/revoke", adminToken, nil, http.StatusOK)
		require.False(t, revoked.Enabled)
		require.True(t, getGate(t, slug, "").ThresholdBreached)
		_, err := time.Parse(time.RFC3339Nano, revoked.UpdatedAt)
		require.NoError(t, err)
	})

	t.Run("a repeated revoke changes nothing and adds no history", func(t *testing.T) {
		again := request[switchedWaiver](t, http.MethodPost, base+"/"+waiver.ID+"/revoke", adminToken,
			map[string]string{}, http.StatusOK)
		require.False(t, again.Enabled)
		require.Equal(t, revoked.UpdatedAt, again.UpdatedAt)
		require.Equal(t, []string{"created", "revoked"}, waiverEventTypes(t, base, waiver.ID))
	})

	var restored switchedWaiver
	t.Run("restoring the waiver silences the gate and names who did it", func(t *testing.T) {
		restored = request[switchedWaiver](t, http.MethodPost, base+"/"+waiver.ID+"/restore", adminToken,
			map[string]string{"expected_updated_at": revoked.UpdatedAt}, http.StatusOK)
		require.True(t, restored.Enabled)
		require.False(t, getGate(t, slug, "").ThresholdBreached)

		events := request[[]switchEvent](t, http.MethodGet, base+"/"+waiver.ID+"/events", adminToken, nil, http.StatusOK)
		require.Equal(t, "restored", events[0].EventType)
		require.Equal(t, admin.ID, events[0].ActorID)
		require.Equal(t, []string{"created", "revoked", "restored"}, waiverEventTypes(t, base, waiver.ID))

		require.NotEmpty(t, auditLines(t, "waiver.revoke"))
		lines := auditLines(t, "waiver.restore")
		require.NotEmpty(t, lines)
		require.Contains(t, lines[len(lines)-1], "principal_id="+admin.ID)
		require.Contains(t, lines[len(lines)-1], "target="+waiver.ID)
	})

	t.Run("a stale Undo cannot override a newer revoke", func(t *testing.T) {
		// A revoked and kept the version from the response. B restored and
		// revoked again since. A's Undo must be refused, not applied.
		aVersion := request[switchedWaiver](t, http.MethodPost, base+"/"+waiver.ID+"/revoke", adminToken, nil, http.StatusOK).UpdatedAt
		request[switchedWaiver](t, http.MethodPost, base+"/"+waiver.ID+"/restore", adminToken, nil, http.StatusOK)
		request[switchedWaiver](t, http.MethodPost, base+"/"+waiver.ID+"/revoke", adminToken, nil, http.StatusOK)

		status, raw := doJSON(t, http.MethodPost, base+"/"+waiver.ID+"/restore", adminToken,
			map[string]string{"expected_updated_at": aVersion})
		require.Equal(t, http.StatusConflict, status, string(raw))
		require.Equal(t, "waiver_changed", errorCode(t, raw))
		require.True(t, getGate(t, slug, "").ThresholdBreached, "the refused Undo must leave the revoke in force")

		// A stale revoke is refused too, although the waiver is already off.
		status, raw = doJSON(t, http.MethodPost, base+"/"+waiver.ID+"/revoke", adminToken,
			map[string]string{"expected_updated_at": aVersion})
		require.Equal(t, http.StatusConflict, status, string(raw))
		require.Equal(t, "waiver_changed", errorCode(t, raw))

		// With the current version the same call goes through.
		current := request[switchedWaiver](t, http.MethodGet, base+"/"+waiver.ID, adminToken, nil, http.StatusOK)
		request[switchedWaiver](t, http.MethodPost, base+"/"+waiver.ID+"/restore", adminToken,
			map[string]string{"expected_updated_at": current.UpdatedAt}, http.StatusOK)
		require.False(t, getGate(t, slug, "").ThresholdBreached)
	})

	t.Run("bad input and missing waivers are refused", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, base+"/"+waiver.ID+"/revoke", adminToken,
			map[string]string{"expected_updated_at": "yesterday"})
		require.Equal(t, http.StatusBadRequest, status, string(raw))
		require.Equal(t, "invalid_expected_updated_at", errorCode(t, raw))

		status, _ = doJSON(t, http.MethodPost, base+"/00000000-0000-0000-0000-00000000dead/restore", adminToken, nil)
		require.Equal(t, http.StatusNotFound, status)
	})

	t.Run("the deprecated toggle still flips an approved waiver", func(t *testing.T) {
		off := request[switchedWaiver](t, http.MethodPost, base+"/"+waiver.ID+"/toggle", adminToken, nil, http.StatusOK)
		require.False(t, off.Enabled)
		on := request[switchedWaiver](t, http.MethodPost, base+"/"+waiver.ID+"/toggle", adminToken, nil, http.StatusOK)
		require.True(t, on.Enabled)
	})

	t.Run("an expired waiver cannot be restored until its expiry is extended", func(t *testing.T) {
		expiresAt := time.Now().Add(4 * time.Second).UTC().Format(time.RFC3339Nano)
		limited := createWaiver(t, slug, "short-window", target.ID, expiresAt)
		eventually(t, 30*time.Second, "sweeper must disable the expired waiver", func() bool {
			got := request[switchedWaiver](t, http.MethodGet, base+"/"+limited.ID, adminToken, nil, http.StatusOK)
			return !got.Enabled
		})

		for _, op := range []string{"restore", "toggle"} {
			status, raw := doJSON(t, http.MethodPost, base+"/"+limited.ID+"/"+op, adminToken, nil)
			require.Equal(t, http.StatusConflict, status, op+": "+string(raw))
			require.Equal(t, "waiver_expired", errorCode(t, raw), op)
		}
		got := request[switchedWaiver](t, http.MethodGet, base+"/"+limited.ID, adminToken, nil, http.StatusOK)
		require.False(t, got.Enabled, "a refused restore must leave the waiver off")

		// Revoking a waiver the sweeper already switched off is a harmless repeat.
		request[switchedWaiver](t, http.MethodPost, base+"/"+limited.ID+"/revoke", adminToken, nil, http.StatusOK)

		later := time.Now().Add(2 * time.Hour).UTC().Format(time.RFC3339)
		request[switchedWaiver](t, http.MethodPut, base+"/"+limited.ID, adminToken,
			map[string]any{"expires_at": later}, http.StatusOK)
		back := request[switchedWaiver](t, http.MethodPost, base+"/"+limited.ID+"/restore", adminToken, nil, http.StatusOK)
		require.True(t, back.Enabled)
	})

	t.Run("a waiver that was never approved cannot be switched", func(t *testing.T) {
		memberToken := login(t, "e2e-viewer@example.com", adminPass)
		memberMe := request[userProfile](t, http.MethodGet, "/api/v1/me", memberToken, nil, http.StatusOK)
		status, raw := doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
			map[string]string{"user_id": memberMe.ID, "role": "member"})
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, status, string(raw))

		var other string
		for _, f := range listFindings(t, slug) {
			if f.ID != target.ID {
				other = f.ID
				break
			}
		}
		require.NotEmpty(t, other)
		pending := request[switchedWaiver](t, http.MethodPost, base+"/requests", memberToken, map[string]any{
			"target_ids": []string{other},
			"reason":     "not reachable",
			"expires_at": time.Now().Add(72 * time.Hour).UTC().Format(time.RFC3339),
		}, http.StatusCreated)
		require.Equal(t, "pending", pending.Status)

		for _, op := range []string{"revoke", "restore", "toggle"} {
			status, raw := doJSON(t, http.MethodPost, base+"/"+pending.ID+"/"+op, adminToken, nil)
			require.Equal(t, http.StatusConflict, status, op+": "+string(raw))
			require.Equal(t, "waiver_not_approved", errorCode(t, raw), op)
		}

		// A project member who is not a manager may not revoke or restore.
		for _, op := range []string{"revoke", "restore"} {
			status, _ := doJSON(t, http.MethodPost, base+"/"+waiver.ID+"/"+op, memberToken, nil)
			require.Equal(t, http.StatusForbidden, status, op)
		}
		require.False(t, getGate(t, slug, "").ThresholdBreached)
	})

	t.Run("an expired waiver no longer counts in the project stats", func(t *testing.T) {
		type counts struct {
			WaiverCount int `json:"waiver_count"`
		}
		before := request[counts](t, http.MethodGet, "/api/v1/projects/"+slug+"/stats", adminToken, nil, http.StatusOK)

		expiresAt := time.Now().Add(3 * time.Second).UTC().Format(time.RFC3339Nano)
		createWaiver(t, slug, "counted-for-a-moment", target.ID, expiresAt)
		during := request[counts](t, http.MethodGet, "/api/v1/projects/"+slug+"/stats", adminToken, nil, http.StatusOK)
		require.Equal(t, before.WaiverCount+1, during.WaiverCount)

		time.Sleep(4 * time.Second)
		after := request[counts](t, http.MethodGet, "/api/v1/projects/"+slug+"/stats", adminToken, nil, http.StatusOK)
		require.Equal(t, before.WaiverCount, after.WaiverCount, "past its expiry the waiver must not count, swept or not")
	})
}
