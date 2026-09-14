package server

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xMinhx/specht/internal/audit"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/usecase"
)

func (h *Handler) TriageFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}

	var req struct {
		AnalysisState     string     `json:"analysis_state"`
		Reason            string     `json:"reason"`
		AnalysisExpiresAt *time.Time `json:"analysis_expires_at,omitempty"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", "invalid request body") {
		return
	}
	if req.AnalysisState == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "analysis_state is required")
		return
	}

	ident := auth.ContextIdentity(r.Context())
	if ident == nil || ident.UserID == "" {
		respondError(w, http.StatusUnauthorized, "unauthorized", "user id required")
		return
	}
	userID := ident.UserID

	result, err := h.usecase.TriageFinding(r.Context(), usecase.TriageInput{
		FindingID:         id,
		AnalysisState:     req.AnalysisState,
		Reason:            req.Reason,
		AnalysisExpiresAt: req.AnalysisExpiresAt,
		UserID:            userID,
	})
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", "finding not found")
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		case errors.Is(err, usecase.ErrReasonRequired):
			respondError(w, http.StatusUnprocessableEntity, "reason_required", "reason is required for this analysis state")
		case errors.Is(err, usecase.ErrExpiryRequired):
			respondError(w, http.StatusUnprocessableEntity, "expiry_required", "expiry is required for accepted_risk and wont_fix")
		case errors.Is(err, usecase.ErrInvalidState):
			respondError(w, http.StatusUnprocessableEntity, "invalid_state", "invalid analysis state")
		default:
			slog.Error("triage finding", "finding_id", id, "error", err)
			respondError(w, http.StatusInternalServerError, "triage_failed", "could not update finding analysis state")
		}
		return
	}
	respondJSON(w, http.StatusOK, result)
	h.audit.HTTP(r, audit.EventTriageFinding, audit.OutcomeSuccess, "", id, nil)
}

func (h *Handler) VerifyFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}
	result, err := h.usecase.VerifyFix(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", "finding not found")
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		default:
			slog.Error("verify finding fix", "finding_id", id, "error", err)
			respondError(w, http.StatusInternalServerError, "verify_failed", "could not verify finding fix")
		}
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) BulkTriage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FindingIDs        []string   `json:"finding_ids"`
		AnalysisState     string     `json:"analysis_state"`
		Reason            string     `json:"reason"`
		AnalysisExpiresAt *time.Time `json:"analysis_expires_at,omitempty"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", "invalid request body") {
		return
	}
	if len(req.FindingIDs) == 0 {
		respondError(w, http.StatusBadRequest, "missing_field", "finding_ids is required")
		return
	}
	if len(req.FindingIDs) > maxBulkFindingIDs {
		respondError(w, http.StatusBadRequest, "too_many_ids", "finding_ids exceeds the maximum of 1000")
		return
	}
	if req.AnalysisState == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "analysis_state is required")
		return
	}

	ident := auth.ContextIdentity(r.Context())
	if ident == nil || ident.UserID == "" {
		respondError(w, http.StatusUnauthorized, "unauthorized", "user id required")
		return
	}
	userID := ident.UserID

	results, err := h.usecase.BulkTriage(r.Context(), usecase.BulkTriageInput{
		FindingIDs:        req.FindingIDs,
		AnalysisState:     req.AnalysisState,
		Reason:            req.Reason,
		AnalysisExpiresAt: req.AnalysisExpiresAt,
		UserID:            userID,
	})
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", "one or more findings not found")
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		case errors.Is(err, usecase.ErrReasonRequired):
			respondError(w, http.StatusUnprocessableEntity, "reason_required", "reason is required for this analysis state")
		case errors.Is(err, usecase.ErrExpiryRequired):
			respondError(w, http.StatusUnprocessableEntity, "expiry_required", "expiry is required for accepted_risk and wont_fix")
		case errors.Is(err, usecase.ErrInvalidState):
			respondError(w, http.StatusUnprocessableEntity, "invalid_state", "invalid analysis state")
		default:
			slog.Error("bulk triage", "error", err)
			respondError(w, http.StatusInternalServerError, "bulk_triage_failed", "could not update finding analysis states")
		}
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (h *Handler) GetGateStatus(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", "project slug is required")
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}

	minRank := parseMinSeverityRank(r.URL.Query().Get("severity"))

	if r.URL.Query().Get("introduced_only") == "1" || r.URL.Query().Get("introduced_only") == "true" {
		reportID := r.URL.Query().Get("report_id")
		if reportID == "" {
			respondError(w, http.StatusBadRequest, "missing_report_id", "report_id is required with introduced_only")
			return
		}
		result, err := h.usecase.GetIntroducedGateStatus(r.Context(), slug, minRank, reportID)
		if err != nil {
			slog.Error("get introduced gate status", "project", slug, "error", err)
			respondError(w, http.StatusInternalServerError, "gate_failed", "could not evaluate gate status")
			return
		}
		respondJSON(w, http.StatusOK, result)
		return
	}

	result, err := h.usecase.GetGateStatus(r.Context(), slug, minRank)
	if err != nil {
		slog.Error("get gate status", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "gate_failed", "could not evaluate gate status")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) PreviewPRCheck(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", "project slug is required")
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}
	q := r.URL.Query()
	commit := q.Get("commit")
	if commit == "" {
		respondError(w, http.StatusBadRequest, "missing_commit", "commit is required")
		return
	}

	result, err := h.usecase.PreviewPRCheck(r.Context(), usecase.PRCheckPreviewInput{
		ProjectSlug:     slug,
		Provider:        q.Get("provider"),
		CommitSha:       commit,
		ReportID:        q.Get("report_id"),
		MinSeverityRank: parseMinSeverityRank(q.Get("severity")),
	})
	if err != nil {
		if errors.Is(err, usecase.ErrUnknownProvider) {
			respondError(w, http.StatusBadRequest, "unknown_provider", "unknown provider")
			return
		}
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this report")
			return
		}
		slog.Error("preview pr check", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "pr_check_failed", "could not plan pull-request check")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) PreviewPatch(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}

	result, err := h.usecase.PreviewPatch(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidFindingID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", "finding not found")
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		default:
			slog.Error("preview patch", "finding_id", id, "error", err)
			respondError(w, http.StatusInternalServerError, "patch_failed", "could not plan patch")
		}
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) PreviewNotification(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}
	q := r.URL.Query()
	channel := q.Get("channel")
	if channel == "" {
		respondError(w, http.StatusBadRequest, "missing_channel", "channel is required (issue or message)")
		return
	}
	target := q.Get("target")
	if target == "" {
		respondError(w, http.StatusBadRequest, "missing_target", "target is required (integration and scope)")
		return
	}
	linked := q.Get("linked") == "1" || q.Get("linked") == "true"

	result, err := h.usecase.PreviewNotification(r.Context(), id, channel, target, linked)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidFindingID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", "finding not found")
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		default:
			slog.Error("preview notification", "finding_id", id, "error", err)
			respondError(w, http.StatusInternalServerError, "notify_failed", "could not plan notification")
		}
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) GetAdminStatus(w http.ResponseWriter, r *http.Request) {
	result, err := h.usecase.GetAdminStatus(r.Context())
	if err != nil {
		slog.Error("get admin status", "error", err)
		respondError(w, http.StatusInternalServerError, "admin_failed", "could not load platform status")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) PreviewRetention(w http.ResponseWriter, r *http.Request) {
	days, ok := parseRetentionDays(w, r)
	if !ok {
		return
	}

	result, err := h.usecase.PreviewRetention(r.Context(), days)
	if err != nil {
		slog.Error("preview retention", "error", err)
		respondError(w, http.StatusInternalServerError, "retention_failed", "could not preview retention")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) PurgeRetention(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OlderThanDays int `json:"older_than_days"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", "invalid request body") {
		return
	}
	if req.OlderThanDays <= 0 || req.OlderThanDays > 3650 {
		respondError(w, http.StatusBadRequest, "invalid_window", "older_than_days must be between 1 and 3650")
		return
	}

	result, err := h.usecase.PurgeRetention(r.Context(), req.OlderThanDays)
	if err != nil {
		slog.Error("purge retention", "error", err)
		respondError(w, http.StatusInternalServerError, "retention_failed", "could not purge reports")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

// parseRetentionDays reads the days query parameter for retention preview.
// It reports false after writing the error response when the window is
// missing or out of range.
func parseRetentionDays(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := r.URL.Query().Get("days")
	days, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || days <= 0 || days > 3650 {
		respondError(w, http.StatusBadRequest, "invalid_window", "days must be between 1 and 3650")
		return 0, false
	}
	return days, true
}

func (h *Handler) ListFindingEvents(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}

	limit := parseIntParam(r, "limit", 50)
	offset := parseIntParam(r, "offset", 0)

	events, err := h.usecase.GetFindingEvents(r.Context(), id, nil, limit, offset)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", "finding not found")
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		default:
			slog.Error("list finding events", "finding_id", id, "error", err)
			respondError(w, http.StatusInternalServerError, "events_failed", "could not list finding events")
		}
		return
	}

	respondJSON(w, http.StatusOK, events)
}

func (h *Handler) ListEnvironments(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", "project slug is required")
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}
	envs, err := h.usecase.ListEnvironments(r.Context(), slug)
	if err != nil {
		slog.Error("list environments", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "environments_failed", "could not list environments")
		return
	}
	respondJSON(w, http.StatusOK, envs)
}

func (h *Handler) ListTargets(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", "project slug is required")
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}
	targets, err := h.usecase.ListTargets(r.Context(), slug)
	if err != nil {
		slog.Error("list targets", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "targets_failed", "could not list targets")
		return
	}
	respondJSON(w, http.StatusOK, targets)
}

func (h *Handler) ListArtifacts(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", "project slug is required")
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}
	artifacts, err := h.usecase.ListArtifacts(r.Context(), slug)
	if err != nil {
		slog.Error("list artifacts", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "artifacts_failed", "could not list artifacts")
		return
	}
	respondJSON(w, http.StatusOK, artifacts)
}

func (h *Handler) GetProjectStats(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", "project slug is required")
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}
	stats, err := h.usecase.GetProjectStats(r.Context(), slug)
	if err != nil {
		slog.Error("get project stats", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "stats_failed", "could not compute project statistics")
		return
	}
	respondJSON(w, http.StatusOK, stats)
}

func (h *Handler) GetAging(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", "project slug is required")
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}
	resp, err := h.usecase.GetAging(r.Context(), slug)
	if err != nil {
		slog.Error("get aging", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "aging_failed", "could not compute aging report")
		return
	}
	respondJSON(w, http.StatusOK, resp)
}
