package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/usecase"
)

func (h *Handler) CreateWaiver(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	var req struct {
		Name        string                               `json:"name"`
		Description string                               `json:"description"`
		Conditions  []usecase.CreateWaiverConditionInput `json:"conditions,omitempty"`
		Contexts    []usecase.CreateWaiverContextInput   `json:"contexts,omitempty"`
		TargetIDs   []string                             `json:"target_ids,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_body", "invalid request body")
		return
	}
	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "invalid_body", "name is required")
		return
	}

	result, err := h.usecase.CreateWaiver(r.Context(), usecase.CreateWaiverInput{
		ProjectSlug: slug,
		Name:        req.Name,
		Description: req.Description,
		Conditions:  req.Conditions,
		Contexts:    req.Contexts,
		TargetIDs:   req.TargetIDs,
		ActorID:     auth.ContextIdentity(r.Context()).UserID,
	})
	if err != nil {
		slog.Error("create waiver", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	respondJSON(w, http.StatusCreated, result)
}

func (h *Handler) ListWaivers(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	waivers, err := h.usecase.ListWaivers(r.Context(), slug)
	if err != nil {
		slog.Error("list waivers", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	respondJSON(w, http.StatusOK, waivers)
}

func (h *Handler) GetWaiver(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	id := chi.URLParam(r, "id")
	waiver, err := h.usecase.GetWaiver(r.Context(), slug, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusNotFound, "not_found", "waiver not found")
		} else {
			slog.Error("get waiver", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}
	respondJSON(w, http.StatusOK, waiver)
}

func (h *Handler) UpdateWaiver(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		Name        string                               `json:"name"`
		Description string                               `json:"description"`
		Conditions  []usecase.CreateWaiverConditionInput `json:"conditions,omitempty"`
		Contexts    []usecase.CreateWaiverContextInput   `json:"contexts,omitempty"`
		TargetIDs   []string                             `json:"target_ids,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_body", "invalid request body")
		return
	}

	result, err := h.usecase.UpdateWaiver(r.Context(), usecase.UpdateWaiverInput{
		WaiverID:    id,
		ProjectSlug: slug,
		Name:        req.Name,
		Description: req.Description,
		Conditions:  req.Conditions,
		Contexts:    req.Contexts,
		TargetIDs:   req.TargetIDs,
		ActorID:     auth.ContextIdentity(r.Context()).UserID,
	})
	if err != nil {
		slog.Error("update waiver", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) DeleteWaiver(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.usecase.DeleteWaiver(r.Context(), slug, id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusNotFound, "not_found", "waiver not found")
		} else {
			slog.Error("delete waiver", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ToggleWaiver(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	id := chi.URLParam(r, "id")
	result, err := h.usecase.ToggleWaiver(r.Context(), slug, id, auth.ContextIdentity(r.Context()).UserID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusNotFound, "not_found", "waiver not found")
		} else {
			slog.Error("toggle waiver", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) ListWaiverEvents(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	id := chi.URLParam(r, "id")
	events, err := h.usecase.ListWaiverEvents(r.Context(), slug, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			respondError(w, http.StatusNotFound, "not_found", "waiver not found")
		} else {
			slog.Error("list waiver events", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}
	respondJSON(w, http.StatusOK, events)
}

func (h *Handler) CheckWaiverMatch(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	var req struct {
		FindingID string `json:"finding_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_body", "invalid request body")
		return
	}
	if req.FindingID == "" {
		respondError(w, http.StatusBadRequest, "invalid_body", "finding_id is required")
		return
	}
	matched, err := h.usecase.CheckWaiverMatch(r.Context(), slug, req.FindingID)
	if err != nil {
		slog.Error("check waiver match", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	respondJSON(w, http.StatusOK, map[string]bool{"matched": matched})
}
