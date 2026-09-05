package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}
	if req.AnalysisState == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "analysis_state is required")
		return
	}

	userID := auth.ContextIdentity(r.Context()).UserID

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
			respondError(w, http.StatusUnprocessableEntity, "reason_required", err.Error())
		case errors.Is(err, usecase.ErrExpiryRequired):
			respondError(w, http.StatusUnprocessableEntity, "expiry_required", err.Error())
		case errors.Is(err, usecase.ErrInvalidState):
			respondError(w, http.StatusUnprocessableEntity, "invalid_state", err.Error())
		default:
			respondError(w, http.StatusInternalServerError, "triage_failed", err.Error())
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}
	if len(req.FindingIDs) == 0 {
		respondError(w, http.StatusBadRequest, "missing_field", "finding_ids is required")
		return
	}
	if req.AnalysisState == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "analysis_state is required")
		return
	}

	userID := auth.ContextIdentity(r.Context()).UserID

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
			respondError(w, http.StatusNotFound, "not_found", err.Error())
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		case errors.Is(err, usecase.ErrReasonRequired):
			respondError(w, http.StatusUnprocessableEntity, "reason_required", err.Error())
		case errors.Is(err, usecase.ErrExpiryRequired):
			respondError(w, http.StatusUnprocessableEntity, "expiry_required", err.Error())
		case errors.Is(err, usecase.ErrInvalidState):
			respondError(w, http.StatusUnprocessableEntity, "invalid_state", err.Error())
		default:
			respondError(w, http.StatusInternalServerError, "bulk_triage_failed", err.Error())
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
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}

	minRank := parseMinSeverityRank(r.URL.Query().Get("severity"))

	result, err := h.usecase.GetGateStatus(r.Context(), slug, minRank)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "gate_failed", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, result)
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
			respondError(w, http.StatusInternalServerError, "events_failed", err.Error())
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
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	envs, err := h.usecase.ListEnvironments(r.Context(), slug)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "environments_failed", err.Error())
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
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	targets, err := h.usecase.ListTargets(r.Context(), slug)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "targets_failed", err.Error())
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
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	artifacts, err := h.usecase.ListArtifacts(r.Context(), slug)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "artifacts_failed", err.Error())
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
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	stats, err := h.usecase.GetProjectStats(r.Context(), slug)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "stats_failed", err.Error())
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
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	resp, err := h.usecase.GetAging(r.Context(), slug)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "aging_failed", err.Error())
		return
	}
	respondJSON(w, http.StatusOK, resp)
}
