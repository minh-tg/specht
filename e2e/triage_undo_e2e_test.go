//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// undoFinding is the part of GET finding the undo tests compare: the whole
// analysis standing, not only the state.
type undoFinding struct {
	ID                string  `json:"id"`
	AnalysisState     string  `json:"analysis_state"`
	GateEffect        string  `json:"gate_effect"`
	AnalysisReason    *string `json:"analysis_reason"`
	AnalysisExpiresAt *string `json:"analysis_expires_at"`
	AnalysisSource    string  `json:"analysis_source"`
	ManualOverride    bool    `json:"manual_override"`
	ReviewRequired    bool    `json:"review_required"`
}

type undoResult struct {
	AnalysisState string `json:"analysis_state"`
	GateEffect    string `json:"gate_effect"`
	EventID       string `json:"event_id"`
}

type undoEvent struct {
	ID        string `json:"id"`
	UserID    string `json:"user_id"`
	EventType string `json:"event_type"`
	Changes   []byte `json:"changes"`
}

func (e undoEvent) undoOfOrEmpty() string {
	var c struct {
		UndoOf string `json:"undo_of"`
	}
	_ = json.Unmarshal(e.Changes, &c)
	return c.UndoOf
}

func (e undoEvent) undoOf(t *testing.T) string {
	t.Helper()
	require.NotEmpty(t, e.Changes)
	return e.undoOfOrEmpty()
}

func undoReadFinding(t *testing.T, id string) undoFinding {
	t.Helper()
	return request[undoFinding](t, http.MethodGet, "/api/v1/findings/"+id, adminToken, nil, http.StatusOK)
}

func undoEvents(t *testing.T, id string) []undoEvent {
	t.Helper()
	return request[[]undoEvent](t, http.MethodGet, "/api/v1/findings/"+id+"/events?limit=100", adminToken, nil, http.StatusOK)
}

// undoSubject ingests the SARIF fixture into a fresh project and returns its
// high finding, which starts unanalyzed and blocking.
func undoSubject(t *testing.T, label string) (slug string, findingID string) {
	t.Helper()
	slug = newProject(t, label)
	ingestFixture(t, slug, mintKey(t, slug), "high-medium.sarif.json")
	return slug, highFinding(t, slug).ID
}

// triageBody builds the PATCH body that puts a finding in state, with the
// reason and expiry the state requires.
func triageBody(state string, expiry time.Time) map[string]any {
	body := map[string]any{"analysis_state": state}
	switch state {
	case "false_positive", "not_affected":
		body["reason"] = "reviewed: " + state
	case "accepted_risk", "wont_fix":
		body["reason"] = "reviewed: " + state
		body["analysis_expires_at"] = expiry.UTC().Format(time.RFC3339Nano)
	}
	return body
}

func triage(t *testing.T, id string, body map[string]any) undoResult {
	t.Helper()
	return request[undoResult](t, http.MethodPatch, "/api/v1/findings/"+id, adminToken, body, http.StatusOK)
}

func undoCall(t *testing.T, token, id, eventID string) (int, []byte) {
	t.Helper()
	return doJSON(t, http.MethodPost, "/api/v1/findings/"+id+"/analysis/undo", token, map[string]string{"event_id": eventID})
}

func requireSameStanding(t *testing.T, want, got undoFinding) {
	t.Helper()
	require.Equal(t, want.AnalysisState, got.AnalysisState)
	require.Equal(t, want.GateEffect, got.GateEffect)
	require.Equal(t, want.AnalysisReason, got.AnalysisReason)
	require.Equal(t, want.AnalysisSource, got.AnalysisSource)
	require.Equal(t, want.ManualOverride, got.ManualOverride)
	require.Equal(t, want.ReviewRequired, got.ReviewRequired)
	if want.AnalysisExpiresAt == nil {
		require.Nil(t, got.AnalysisExpiresAt)
		return
	}
	require.NotNil(t, got.AnalysisExpiresAt)
	wantAt, err := time.Parse(time.RFC3339Nano, *want.AnalysisExpiresAt)
	require.NoError(t, err)
	gotAt, err := time.Parse(time.RFC3339Nano, *got.AnalysisExpiresAt)
	require.NoError(t, err)
	require.True(t, wantAt.Equal(gotAt), "expiry: want %s got %s", wantAt, gotAt)
}

// TestE2E_TriageUndo_RestoresEveryPreviousState moves a finding into each
// analysis state, triages it elsewhere, undoes that, and checks the finding
// is back exactly as it was, including reason, expiry, source and flags.
func TestE2E_TriageUndo_RestoresEveryPreviousState(t *testing.T) {
	states := []string{"unanalyzed", "in_triage", "exploitable", "false_positive", "not_affected", "accepted_risk", "wont_fix"}
	for _, previous := range states {
		t.Run("from "+previous, func(t *testing.T) {
			slug, id := undoSubject(t, "undo-"+strings.ReplaceAll(previous, "_", "-"))
			if previous != "unanalyzed" {
				triage(t, id, triageBody(previous, time.Now().Add(24*time.Hour)))
			}
			want := undoReadFinding(t, id)
			require.Equal(t, previous, want.AnalysisState)
			if previous == "unanalyzed" {
				require.Equal(t, "system", want.AnalysisSource, "a fresh finding was never set by a person")
				require.False(t, want.ManualOverride)
			}
			wantGate := getGate(t, slug, "")
			eventsBefore := len(undoEvents(t, id))

			next := "in_triage"
			if previous == "in_triage" {
				next = "exploitable"
			}
			changed := triage(t, id, triageBody(next, time.Now().Add(24*time.Hour)))
			require.NotEmpty(t, changed.EventID)
			require.Equal(t, next, undoReadFinding(t, id).AnalysisState)

			status, raw := undoCall(t, adminToken, id, changed.EventID)
			require.Equalf(t, http.StatusOK, status, "%s\n%s", raw, serverLogTail())
			var restored undoResult
			require.NoError(t, json.Unmarshal(raw, &restored))
			require.Equal(t, previous, restored.AnalysisState)
			require.Equal(t, want.GateEffect, restored.GateEffect)
			require.NotEmpty(t, restored.EventID)
			require.NotEqual(t, changed.EventID, restored.EventID)

			requireSameStanding(t, want, undoReadFinding(t, id))
			gate := getGate(t, slug, "")
			require.Equal(t, wantGate.ThresholdBreached, gate.ThresholdBreached)
			require.Equal(t, wantGate.BlockingCount, gate.BlockingCount)

			events := undoEvents(t, id)
			require.Len(t, events, eventsBefore+2, "the triage and the undo are both recorded")
			require.Equal(t, restored.EventID, events[0].ID, "the undo is the newest event")
			require.Equal(t, "analysis_changed", events[0].EventType)
			require.Equal(t, changed.EventID, events[0].undoOf(t))
			var original bool
			for _, e := range events {
				original = original || e.ID == changed.EventID
			}
			require.True(t, original, "the undone event is not deleted")
		})
	}
}

func TestE2E_TriageUndo_OnlyTheNewestChangeCanBeUndone(t *testing.T) {
	_, id := undoSubject(t, "undo-newest")
	first := triage(t, id, triageBody("in_triage", time.Time{}))
	second := triage(t, id, triageBody("exploitable", time.Time{}))

	status, raw := undoCall(t, adminToken, id, first.EventID)
	require.Equal(t, http.StatusConflict, status, string(raw))
	require.Contains(t, string(raw), "analysis_conflict")
	require.Equal(t, "exploitable", undoReadFinding(t, id).AnalysisState, "a refused undo changes nothing")

	status, raw = undoCall(t, adminToken, id, second.EventID)
	require.Equal(t, http.StatusOK, status, string(raw))
	var undone undoResult
	require.NoError(t, json.Unmarshal(raw, &undone))
	require.Equal(t, "in_triage", undone.AnalysisState)

	status, raw = undoCall(t, adminToken, id, second.EventID)
	require.Equal(t, http.StatusConflict, status, "the same undo cannot run twice: %s", raw)
	require.Contains(t, string(raw), "analysis_conflict")

	status, raw = undoCall(t, adminToken, id, undone.EventID)
	require.Equal(t, http.StatusOK, status, "an undo can itself be undone: %s", raw)
	require.Equal(t, "exploitable", undoReadFinding(t, id).AnalysisState)

	status, raw = undoCall(t, adminToken, id, "00000000-0000-0000-0000-00000000dead")
	require.Equal(t, http.StatusConflict, status, string(raw))
	status, raw = undoCall(t, adminToken, id, "not-a-uuid")
	require.Equal(t, http.StatusBadRequest, status, string(raw))
}

func TestE2E_TriageExpectedState(t *testing.T) {
	_, id := undoSubject(t, "undo-expected")

	body := triageBody("in_triage", time.Time{})
	body["expected_state"] = "exploitable"
	status, raw := doJSON(t, http.MethodPatch, "/api/v1/findings/"+id, adminToken, body)
	require.Equal(t, http.StatusConflict, status, string(raw))
	require.Contains(t, string(raw), "analysis_conflict")
	require.Equal(t, "unanalyzed", undoReadFinding(t, id).AnalysisState)

	body["expected_state"] = "unanalyzed"
	out := request[undoResult](t, http.MethodPatch, "/api/v1/findings/"+id, adminToken, body, http.StatusOK)
	require.Equal(t, "in_triage", out.AnalysisState)
}

func TestE2E_TriageUndo_RefusesWhatCannotBeRestored(t *testing.T) {
	t.Run("a bulk triage event has no snapshot", func(t *testing.T) {
		slug, id := undoSubject(t, "undo-bulk")
		_ = slug
		request[map[string]any](t, http.MethodPost, "/api/v1/findings/bulk-analysis", adminToken,
			map[string]any{"finding_ids": []string{id}, "analysis_state": "in_triage"}, http.StatusOK)
		var bulkID string
		for _, e := range undoEvents(t, id) {
			if e.EventType == "bulk_triage_applied" {
				bulkID = e.ID
			}
		}
		require.NotEmpty(t, bulkID)

		status, raw := undoCall(t, adminToken, id, bulkID)
		require.Equal(t, http.StatusConflict, status, string(raw))
		require.Contains(t, string(raw), "undo_unavailable")
		require.Equal(t, "in_triage", undoReadFinding(t, id).AnalysisState)
	})

	t.Run("the earlier decision has expired", func(t *testing.T) {
		_, id := undoSubject(t, "undo-expired")
		triage(t, id, triageBody("accepted_risk", time.Now().Add(3*time.Second)))
		changed := triage(t, id, triageBody("in_triage", time.Time{}))

		time.Sleep(4 * time.Second)

		status, raw := undoCall(t, adminToken, id, changed.EventID)
		require.Equal(t, http.StatusConflict, status, string(raw))
		require.Contains(t, string(raw), "previous_expiry_passed")
		require.Equal(t, "in_triage", undoReadFinding(t, id).AnalysisState)
	})
}

func TestE2E_TriageUndo_Permissions(t *testing.T) {
	slug, id := undoSubject(t, "undo-perms")
	userToken := login(t, "e2e-viewer@example.com", adminPass)
	me := request[userProfile](t, http.MethodGet, "/api/v1/me", userToken, nil, http.StatusOK)
	setRole := func(role string) {
		t.Helper()
		status, raw := doJSON(t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
			map[string]string{"user_id": me.ID, "role": role})
		require.Contains(t, []int{http.StatusOK, http.StatusCreated}, status, string(raw))
	}
	changed := triage(t, id, triageBody("in_triage", time.Time{}))

	setRole("member")
	status, raw := undoCall(t, userToken, id, changed.EventID)
	require.Equal(t, http.StatusForbidden, status, string(raw))
	require.Equal(t, "in_triage", undoReadFinding(t, id).AnalysisState)

	status, raw = undoCall(t, "", id, changed.EventID)
	require.Equal(t, http.StatusUnauthorized, status, string(raw))

	setRole("manager")
	status, raw = undoCall(t, userToken, id, changed.EventID)
	require.Equal(t, http.StatusOK, status, "a manager may undo a change an admin made: %s", raw)
	require.Equal(t, "unanalyzed", undoReadFinding(t, id).AnalysisState)

	var actor string
	for _, e := range undoEvents(t, id) {
		if e.undoOfOrEmpty() == changed.EventID {
			actor = e.UserID
		}
	}
	require.Equal(t, me.ID, actor, "the undo is attributed to the person who ran it")
}
