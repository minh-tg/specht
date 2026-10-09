//go:build e2e

package e2e

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Local response shapes for the assessment endpoints: bulk triage,
// evidence, reachability, signoff, and fix verification.

type reachabilityResponse struct {
	ID         string `json:"id"`
	FindingID  string `json:"finding_id"`
	State      string `json:"state"`
	Evidence   string `json:"evidence"`
	AssessedBy string `json:"assessed_by"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

type evidenceResponse struct {
	ID          string  `json:"id"`
	FindingID   string  `json:"finding_id"`
	Type        string  `json:"type"`
	URL         string  `json:"url"`
	Description string  `json:"description"`
	UploadedBy  *string `json:"uploaded_by"`
	CreatedAt   string  `json:"created_at"`
}

type signoffResponse struct {
	ID         string `json:"id"`
	FindingID  string `json:"finding_id"`
	Status     string `json:"status"`
	ReviewedBy string `json:"reviewed_by"`
	Comment    string `json:"comment"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

type verifyResponse struct {
	FindingID string  `json:"finding_id"`
	Outcome   string  `json:"outcome"`
	ReportID  *string `json:"report_id"`
	Detail    string  `json:"detail"`
}

// TestE2E_AssessmentFlows walks the analyst assessment processes end to
// end: reachability (including the gate exemption), evidence, signoff, the
// full triage-state vocabulary, bulk triage, and fix verification — each
// with its validation, denial, and malformed-id contracts.
func TestE2E_AssessmentFlows(t *testing.T) {
	slug := newProject(t, "assess")
	key := mintKey(t, slug)
	ingestFixture(t, slug, key, "high-medium.sarif.json")

	high := highFinding(t, slug)
	var medium findingResponse
	for _, f := range listFindings(t, slug) {
		if f.ID != high.ID {
			medium = f
		}
	}
	require.NotEmpty(t, medium.ID, "the fixture carries two findings")

	adminMe := request[userProfile](t, http.MethodGet, "/api/v1/me", adminToken, nil, http.StatusOK)
	viewerToken := login(t, "e2e-viewer@example.com", adminPass)
	viewerMe := request[userProfile](t, http.MethodGet, "/api/v1/me", viewerToken, nil, http.StatusOK)
	request[memberResponse](t, http.MethodPost, "/api/v1/projects/"+slug+"/members", adminToken,
		map[string]string{"user_id": viewerMe.ID, "role": "viewer"}, http.StatusCreated)

	t.Run("reachability assesses and exempts the gate", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/findings/"+high.ID+"/reachability", viewerToken,
			map[string]string{"state": "reachable"})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"a viewer member cannot assess reachability")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/"+high.ID+"/reachability", key,
			map[string]string{"state": "reachable"})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_scope", errorCode(t, raw),
			"a project key without admin scope cannot assess reachability")

		assessed := request[reachabilityResponse](t, http.MethodPost,
			"/api/v1/findings/"+high.ID+"/reachability", adminToken,
			map[string]string{"state": "reachable", "evidence": "call path confirmed reachable"}, http.StatusOK)
		require.Equal(t, high.ID, assessed.FindingID)
		require.Equal(t, "reachable", assessed.State)
		require.Equal(t, "call path confirmed reachable", assessed.Evidence)
		require.Equal(t, adminMe.ID, assessed.AssessedBy)
		require.NotEmpty(t, assessed.CreatedAt)
		require.NotEmpty(t, assessed.UpdatedAt)

		gs := getGate(t, slug, "")
		require.True(t, gs.ThresholdBreached, "a reachable assessment never exempts the gate")
		require.Equal(t, "reachable", gs.BlockedByReachability[high.ID],
			"the gate explains each blocker with its latest assessment")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/"+high.ID+"/reachability", adminToken,
			map[string]string{"state": "maybe"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_state", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/not-a-uuid/reachability", adminToken,
			map[string]string{"state": "reachable"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_id", errorCode(t, raw))

		unknown := randomHex(16)
		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/"+unknown+"/reachability", adminToken,
			map[string]string{"state": "reachable"})
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw))

		exempt := request[reachabilityResponse](t, http.MethodPost,
			"/api/v1/findings/"+high.ID+"/reachability", adminToken,
			map[string]string{"state": "not_reachable"}, http.StatusOK)
		require.Equal(t, assessed.ID, exempt.ID, "assessment upserts in place")

		gs = getGate(t, slug, "")
		require.False(t, gs.ThresholdBreached,
			"a not_reachable assessment exempts the finding from the gate")
		require.Zero(t, gs.BlockingCount)

		list := request[[]reachabilityResponse](t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/reachability", key, nil, http.StatusOK)
		require.Len(t, list, 1, "a project key with read scope may read assessments")
		require.Equal(t, "not_reachable", list[0].State)

		request[reachabilityResponse](t, http.MethodPost,
			"/api/v1/findings/"+high.ID+"/reachability", adminToken,
			map[string]string{"state": "reachable"}, http.StatusOK)
		require.True(t, getGate(t, slug, "").ThresholdBreached,
			"lifting the exemption restores the block")
	})

	t.Run("evidence attaches, lists, and deletes", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/findings/"+high.ID+"/evidence", viewerToken,
			map[string]string{"type": "ticket"})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"a viewer member cannot attach evidence")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/"+high.ID+"/evidence", key,
			map[string]string{"type": "ticket"})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_scope", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/"+high.ID+"/evidence", adminToken,
			map[string]string{"url": "https://example.com/t/1"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "missing_field", errorCode(t, raw), "type is required")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/"+high.ID+"/evidence", adminToken,
			map[string]string{"type": "ticket"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_type", errorCode(t, raw),
			"types outside the persistence vocabulary are rejected at the boundary")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/not-a-uuid/evidence", adminToken,
			map[string]string{"type": "ticket"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_id", errorCode(t, raw))

		unknown := randomHex(16)
		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/"+unknown+"/evidence", adminToken,
			map[string]string{"type": "ticket"})
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw))

		created := request[evidenceResponse](t, http.MethodPost,
			"/api/v1/findings/"+high.ID+"/evidence", adminToken,
			map[string]string{
				"type": "reference", "url": "https://example.com/t/1",
				"description": "vendor acknowledged",
			}, http.StatusCreated)
		require.Equal(t, high.ID, created.FindingID)
		require.Equal(t, "reference", created.Type)
		require.Equal(t, "https://example.com/t/1", created.URL)
		require.Equal(t, "vendor acknowledged", created.Description)
		require.NotNil(t, created.UploadedBy)
		require.Equal(t, adminMe.ID, *created.UploadedBy)
		require.NotEmpty(t, created.CreatedAt)

		list := request[[]evidenceResponse](t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/evidence", viewerToken, nil, http.StatusOK)
		require.Len(t, list, 1, "membership grants evidence reads")
		require.Equal(t, created.ID, list[0].ID)

		status, _ = doJSON(t, http.MethodDelete,
			"/api/v1/findings/"+high.ID+"/evidence/"+created.ID, viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status,
			"a viewer member cannot detach evidence")

		status, raw = doJSON(t, http.MethodDelete,
			"/api/v1/findings/"+high.ID+"/evidence/"+created.ID, key, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_scope", errorCode(t, raw))

		status, _ = doJSON(t, http.MethodDelete,
			"/api/v1/findings/"+high.ID+"/evidence/"+created.ID, adminToken, nil)
		require.Equal(t, http.StatusNoContent, status)
		require.Empty(t, request[[]evidenceResponse](t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/evidence", adminToken, nil, http.StatusOK))

		status, raw = doJSON(t, http.MethodDelete,
			"/api/v1/findings/"+high.ID+"/evidence/"+created.ID, adminToken, nil)
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw),
			"deleting missing evidence reports 404, not a server error")

		status, raw = doJSON(t, http.MethodDelete,
			"/api/v1/findings/"+high.ID+"/evidence/not-a-uuid", adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_id", errorCode(t, raw))
	})

	t.Run("signoff records reviewer decisions", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodGet, "/api/v1/findings/"+high.ID+"/signoff", adminToken, nil)
		require.Equal(t, http.StatusNotFound, status,
			"no signoff exists before the first review")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/"+high.ID+"/signoff", viewerToken,
			map[string]string{"status": "approved"})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"a viewer member cannot sign off")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/"+high.ID+"/signoff", adminToken,
			map[string]string{"status": "maybe"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_status", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/not-a-uuid/signoff", adminToken,
			map[string]string{"status": "approved"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_id", errorCode(t, raw))

		approved := request[signoffResponse](t, http.MethodPost,
			"/api/v1/findings/"+high.ID+"/signoff", adminToken,
			map[string]string{"status": "approved", "comment": "reviewed against source"},
			http.StatusOK)
		require.Equal(t, high.ID, approved.FindingID)
		require.Equal(t, "approved", approved.Status)
		require.Equal(t, adminMe.ID, approved.ReviewedBy)
		require.Equal(t, "reviewed against source", approved.Comment)
		require.NotEmpty(t, approved.CreatedAt)

		got := request[signoffResponse](t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/signoff", adminToken, nil, http.StatusOK)
		require.Equal(t, approved.ID, got.ID)
		require.Equal(t, "approved", got.Status)

		rejected := request[signoffResponse](t, http.MethodPost,
			"/api/v1/findings/"+high.ID+"/signoff", adminToken,
			map[string]string{"status": "rejected", "comment": "needs rework"}, http.StatusOK)
		require.Equal(t, approved.ID, rejected.ID, "signoff upserts in place")
		require.Equal(t, "rejected", rejected.Status)
		require.Equal(t, "needs rework", rejected.Comment)
	})

	t.Run("the triage-state vocabulary drives the gate", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPatch, "/api/v1/findings/"+high.ID, viewerToken,
			map[string]any{"analysis_state": "exploitable"})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"a viewer member cannot triage")

		status, raw = doJSON(t, http.MethodPatch, "/api/v1/findings/not-a-uuid", adminToken,
			map[string]any{"analysis_state": "exploitable"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_id", errorCode(t, raw))

		unknown := randomHex(16)
		status, raw = doJSON(t, http.MethodPatch, "/api/v1/findings/"+unknown, adminToken,
			map[string]any{"analysis_state": "exploitable"})
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw))

		inTriage := request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+high.ID, adminToken,
			map[string]any{"analysis_state": "in_triage"}, http.StatusOK)
		require.Equal(t, "in_triage", inTriage.AnalysisState)
		require.Equal(t, "block", inTriage.GateEffect, "in-triage still blocks")

		exploitable := request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+high.ID, adminToken,
			map[string]any{"analysis_state": "exploitable"}, http.StatusOK)
		require.Equal(t, "exploitable", exploitable.AnalysisState)
		require.Equal(t, "block", exploitable.GateEffect)
		require.True(t, getGate(t, slug, "").ThresholdBreached)

		status, raw = doJSON(t, http.MethodPatch, "/api/v1/findings/"+high.ID, adminToken,
			map[string]any{"analysis_state": "false_positive"})
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Equal(t, "reason_required", errorCode(t, raw))

		fp := request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+high.ID, adminToken,
			map[string]any{"analysis_state": "false_positive", "reason": "scanner emitted a test fixture"},
			http.StatusOK)
		require.Equal(t, "ignore", fp.GateEffect)
		require.False(t, getGate(t, slug, "").ThresholdBreached,
			"an ignored finding leaves only below-floor medium debt")

		status, raw = doJSON(t, http.MethodPatch, "/api/v1/findings/"+high.ID, adminToken,
			map[string]any{"analysis_state": "not_affected"})
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Equal(t, "reason_required", errorCode(t, raw))

		na := request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+high.ID, adminToken,
			map[string]any{"analysis_state": "not_affected", "reason": "code path unreachable in build"}, http.StatusOK)
		require.Equal(t, "ignore", na.GateEffect)

		status, raw = doJSON(t, http.MethodPatch, "/api/v1/findings/"+high.ID, adminToken,
			map[string]any{"analysis_state": "wont_fix", "reason": "accepted for 2.0"})
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Equal(t, "expiry_required", errorCode(t, raw),
			"reason is present, so the expiry requirement fires")

		status, raw = doJSON(t, http.MethodPatch, "/api/v1/findings/"+high.ID, adminToken,
			map[string]any{"analysis_state": "wont_fix"})
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Equal(t, "reason_required", errorCode(t, raw),
			"reason is checked before expiry")

		wontFix := request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+high.ID, adminToken,
			map[string]any{
				"analysis_state": "wont_fix", "reason": "accepted for 2.0",
				"analysis_expires_at": time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano),
			},
			http.StatusOK)
		require.Equal(t, "ignore", wontFix.GateEffect)

		back := request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+high.ID, adminToken,
			map[string]any{"analysis_state": "exploitable"}, http.StatusOK)
		require.Equal(t, "block", back.GateEffect)
		require.True(t, getGate(t, slug, "").ThresholdBreached,
			"restoring an actionable state re-blocks the gate")
	})

	t.Run("bulk triage applies one decision across findings", func(t *testing.T) {
		ids := []string{high.ID, medium.ID}

		status, raw := doJSON(t, http.MethodPost, "/api/v1/findings/bulk-analysis", viewerToken,
			map[string]any{"finding_ids": ids, "analysis_state": "false_positive", "reason": "r"})
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"a viewer member cannot bulk triage")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/bulk-analysis", adminToken,
			map[string]any{"analysis_state": "false_positive"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "missing_field", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/bulk-analysis", adminToken,
			map[string]any{"finding_ids": ids})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "missing_field", errorCode(t, raw))

		many := make([]string, 0, 1001)
		for i := 0; i < 1001; i++ {
			many = append(many, randomHex(16))
		}
		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/bulk-analysis", adminToken,
			map[string]any{"finding_ids": many, "analysis_state": "false_positive"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "too_many_ids", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/bulk-analysis", adminToken,
			map[string]any{"finding_ids": ids, "analysis_state": "shrug"})
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Equal(t, "invalid_state", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/bulk-analysis", adminToken,
			map[string]any{"finding_ids": []string{"not-a-uuid"}, "analysis_state": "false_positive"})
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_id", errorCode(t, raw))

		unknown := randomHex(16)
		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/bulk-analysis", adminToken,
			map[string]any{"finding_ids": []string{unknown}, "analysis_state": "false_positive"})
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/bulk-analysis", adminToken,
			map[string]any{"finding_ids": ids, "analysis_state": "false_positive"})
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Equal(t, "reason_required", errorCode(t, raw))

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/bulk-analysis", adminToken,
			map[string]any{"finding_ids": ids, "analysis_state": "wont_fix", "reason": "deferred"})
		require.Equal(t, http.StatusUnprocessableEntity, status)
		require.Equal(t, "expiry_required", errorCode(t, raw))

		bulk := request[struct {
			Results []triageOutput `json:"results"`
		}](t, http.MethodPost, "/api/v1/findings/bulk-analysis", adminToken,
			map[string]any{
				"finding_ids": ids, "analysis_state": "false_positive",
				"reason": "both are scanner fixtures",
			}, http.StatusOK)
		require.Len(t, bulk.Results, 2)
		for _, r := range bulk.Results {
			require.Equal(t, "false_positive", r.AnalysisState)
			require.Equal(t, "ignore", r.GateEffect)
		}
		require.False(t, getGate(t, slug, "").ThresholdBreached,
			"bulk-ignoring both findings opens the gate")

		events := request[[]findingEvent](t, http.MethodGet,
			"/api/v1/findings/"+high.ID+"/events", adminToken, nil, http.StatusOK)
		types := make([]string, 0, len(events))
		for _, e := range events {
			types = append(types, e.EventType)
		}
		require.Contains(t, types, "bulk_triage_applied",
			"bulk decisions land in the audit trail")
	})

	t.Run("verification settles against real rescan evidence", func(t *testing.T) {
		status, raw := doJSON(t, http.MethodPost, "/api/v1/findings/"+high.ID+"/verify", viewerToken, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "project_access_denied", errorCode(t, raw),
			"a viewer member cannot verify")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/not-a-uuid/verify", adminToken, nil)
		require.Equal(t, http.StatusBadRequest, status)
		require.Equal(t, "invalid_id", errorCode(t, raw))

		unknown := randomHex(16)
		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/"+unknown+"/verify", adminToken, nil)
		require.Equal(t, http.StatusNotFound, status)
		require.Equal(t, "not_found", errorCode(t, raw))

		present := request[verifyResponse](t, http.MethodPost,
			"/api/v1/findings/"+high.ID+"/verify", adminToken, nil, http.StatusOK)
		require.Equal(t, high.ID, present.FindingID)
		require.Equal(t, "still_present", present.Outcome,
			"the latest completed report still observes the finding")
		require.NotNil(t, present.ReportID)
		require.NotEmpty(t, present.Detail)

		detail := request[findingResponse](t, http.MethodGet,
			"/api/v1/findings/"+high.ID, adminToken, nil, http.StatusOK)
		require.Equal(t, "false_positive", detail.AnalysisState,
			"verification never disturbs the analyst's triage standing")

		ingestFixture(t, slug, key, "medium.sarif.json")

		inconclusive := request[verifyResponse](t, http.MethodPost,
			"/api/v1/findings/"+high.ID+"/verify", adminToken, nil, http.StatusOK)
		require.Equal(t, "inconclusive", inconclusive.Outcome,
			"a scan without complete scope cannot settle a fix")
		require.Contains(t, inconclusive.Detail, "not complete")

		status, raw = doJSON(t, http.MethodPost, "/api/v1/findings/"+high.ID+"/verify", key, nil)
		require.Equal(t, http.StatusForbidden, status)
		require.Equal(t, "insufficient_scope", errorCode(t, raw))
	})

	t.Run("verification is bound to the finding's scan scope", func(t *testing.T) {
		slug := newProject(t, "verify-fixed")
		first := ingestRaw(t, slug, "trivy", "trivy-alpine-scan.json",
			map[string]any{"branch": "main", "commit_sha": baseSHA})
		findings := listScanFindings(t, slug)
		require.Len(t, findings, 2)
		target := findings[0]

		// The analyst's standing must survive verification.
		request[triageOutput](t, http.MethodPatch, "/api/v1/findings/"+target.ID, adminToken,
			map[string]any{"analysis_state": "false_positive", "reason": "already mitigated"},
			http.StatusOK)

		// A newer COMPLETE trivy report from another branch lacks the finding.
		// It is outside the finding's scan scope, so neither the auto-fix writer
		// nor verification may use it.
		other := ingestRaw(t, slug, "trivy", "trivy-empty-scan.json",
			map[string]any{"branch": "release", "commit_sha": deadSHA})
		require.Zero(t, other.TotalFindings)
		for _, f := range listScanFindings(t, slug) {
			require.Equal(t, "open", f.State,
				"scope-mismatched scans never auto-close")
		}

		// The main-branch report still observes the finding, and it is the
		// newest report in the finding's scope, so the verdict is still_present
		// and names that report rather than the release scan.
		present := request[verifyResponse](t, http.MethodPost,
			"/api/v1/findings/"+target.ID+"/verify", adminToken, nil, http.StatusOK)
		require.Equal(t, "still_present", present.Outcome)
		require.NotNil(t, present.ReportID)
		require.Equal(t, first.ReportID, *present.ReportID,
			"the verdict names the finding's own scope, not the release scan")

		// A complete main-branch rescan at a new commit lacks the finding. It is
		// in the same scope, so the auto-fix writer closes the finding at ingest.
		// The payload differs from the release scan, since identical bytes are
		// rejected as duplicates.
		rescanSHA := "2222222222222222222222222222222222222222"
		rescan := ingestRaw(t, slug, "trivy", "trivy-empty-rescan.json",
			map[string]any{"branch": "main", "commit_sha": rescanSHA})
		require.Zero(t, rescan.TotalFindings)

		closed := request[scanFinding](t, http.MethodGet,
			"/api/v1/findings/"+target.ID, adminToken, nil, http.StatusOK)
		require.Equal(t, "fixed", closed.State,
			"the same-scope rescan closes the finding at ingest")
		require.Equal(t, "false_positive", closed.AnalysisState,
			"auto-fix moves scan state, never analyst state")

		// Verification on the already-fixed finding names the same-scope rescan.
		verified := request[verifyResponse](t, http.MethodPost,
			"/api/v1/findings/"+target.ID+"/verify", adminToken, nil, http.StatusOK)
		require.Equal(t, "verified_fixed", verified.Outcome)
		require.NotNil(t, verified.ReportID)
		require.Equal(t, rescan.ReportID, *verified.ReportID,
			"the verdict names the same-scope report that lacks the finding")

		detail := request[scanFinding](t, http.MethodGet,
			"/api/v1/findings/"+target.ID, adminToken, nil, http.StatusOK)
		require.Equal(t, "fixed", detail.State)
		require.Equal(t, "false_positive", detail.AnalysisState,
			"verification moves scan state, never analyst state")

		events := request[[]auditEvent](t, http.MethodGet,
			"/api/v1/findings/"+target.ID+"/events", adminToken, nil, http.StatusOK)
		var types []string
		for _, e := range events {
			types = append(types, e.EventType)
		}
		require.Contains(t, types, "verified_fixed",
			"the verdict lands in the audit trail")
	})
}
