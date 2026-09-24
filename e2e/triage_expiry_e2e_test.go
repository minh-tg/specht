//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestE2E_TriageAndAnalysisExpirySweep covers the analyst workflow end to
// end: validation rules, accepting risk with an expiry window (gate opens),
// and the background sweeper closing the window again with a system audit
// event (gate re-blocks).
func TestE2E_TriageAndAnalysisExpirySweep(t *testing.T) {
	slug := newProject(t, "triage")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high-medium.sarif.json")
	target := highFinding(t, slug)

	t.Run("accepted_risk requires a reason", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPatch, "/api/v1/findings/"+target.ID, adminToken,
			map[string]any{"analysis_state": "accepted_risk"})
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Contains(t, string(raw), "reason_required")
	})

	t.Run("accepted_risk requires an expiry", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPatch, "/api/v1/findings/"+target.ID, adminToken,
			map[string]any{"analysis_state": "accepted_risk", "reason": "risk accepted for release"})
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Contains(t, string(raw), "expiry_required")
	})

	t.Run("unknown analysis states are rejected", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPatch, "/api/v1/findings/"+target.ID, adminToken,
			map[string]any{"analysis_state": "shrug", "reason": "x"})
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Contains(t, string(raw), "invalid_state")
	})

	expiry := time.Now().Add(5 * time.Second)
	t.Run("accepting risk opens the gate with a recorded reason", func(t *testing.T) {
		out := request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+target.ID, adminToken,
			map[string]any{
				"analysis_state":      "accepted_risk",
				"reason":              "accepted for the 1.4 release, ticket SEC-114",
				"analysis_expires_at": expiry.UTC().Format(time.RFC3339Nano),
			}, http.StatusOK)
		require.Equal(t, "accepted_risk", out.AnalysisState)
		require.Equal(t, "ignore", out.GateEffect)

		gs := getGate(t, slug, "")
		require.False(t, gs.ThresholdBreached, "accepted_risk must not block the gate")
		require.Zero(t, gs.BlockingCount)

		events := request[[]findingEvent](t, http.MethodGet,
			"/api/v1/findings/"+target.ID+"/events", adminToken, nil, http.StatusOK)
		require.Contains(t, eventComments(events), "accepted for the 1.4 release, ticket SEC-114")
	})

	t.Run("sweeper expires the acceptance and re-blocks the gate", func(t *testing.T) {
		// The server sweeps every second (LIFECYCLE_SWEEP_INTERVAL); once
		// the 5s window passes the finding must return to unanalyzed/block
		// and carry a system audit event.
		eventually(t, 30*time.Second, "sweeper must reset the expired acceptance", func() bool {
			f := request[findingResponse](t, http.MethodGet,
				"/api/v1/findings/"+target.ID, adminToken, nil, http.StatusOK)
			return f.AnalysisState == "unanalyzed" && f.GateEffect == "block"
		})

		gs := getGate(t, slug, "")
		require.True(t, gs.ThresholdBreached, "gate must re-block after the acceptance expires")
		require.EqualValues(t, 1, gs.BlockingCount)

		events := request[[]findingEvent](t, http.MethodGet,
			"/api/v1/findings/"+target.ID+"/events", adminToken, nil, http.StatusOK)
		require.Contains(t, eventComments(events), "analysis expired, reset to unanalyzed",
			"the sweeper must leave a system audit event")
	})
}

// eventComments extracts comment texts from finding events, tolerating any
// ordering (the API sorts newest-first).
func eventComments(events []findingEvent) []string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		if e.Comment != nil {
			out = append(out, *e.Comment)
		}
	}
	return out
}
