package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/usecase"
)

func (h *Handler) CreateEvidence(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}
	var req struct {
		Type        string `json:"type"`
		URL         string `json:"url"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}
	if req.Type == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "type is required")
		return
	}

	userID := auth.ContextIdentity(r.Context()).UserID

	result, err := h.usecase.CreateEvidence(r.Context(), findingID, userID, req.Type, req.URL, req.Description)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", "finding not found")
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		default:
			slog.Error("create evidence", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}
	respondJSON(w, http.StatusCreated, result)
}

func (h *Handler) ListEvidence(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}
	result, err := h.usecase.ListEvidence(r.Context(), findingID)
	if err != nil {
		slog.Error("list evidence", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) DeleteEvidence(w http.ResponseWriter, r *http.Request) {
	evidenceID := chi.URLParam(r, "evidenceID")
	if evidenceID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "evidence id is required")
		return
	}
	if err := h.usecase.DeleteEvidence(r.Context(), evidenceID); err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		} else {
			slog.Error("delete evidence", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) UpsertReachability(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}
	var req struct {
		State    string `json:"state"`
		Evidence string `json:"evidence"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}

	ident := auth.ContextIdentity(r.Context())
	if ident == nil || ident.UserID == "" {
		respondError(w, http.StatusUnauthorized, "unauthorized", "user id required")
		return
	}

	result, err := h.usecase.UpsertReachability(r.Context(), findingID, ident.UserID, req.State, req.Evidence)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidReachabilityState):
			respondError(w, http.StatusBadRequest, "invalid_state", err.Error())
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", "finding not found")
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		default:
			slog.Error("upsert reachability", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) ListReachability(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}
	result, err := h.usecase.ListReachability(r.Context(), findingID)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", "finding not found")
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		default:
			slog.Error("list reachability", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) UpsertSignoff(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}
	var req struct {
		Status  string `json:"status"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}
	if req.Status != "approved" && req.Status != "rejected" && req.Status != "pending" {
		respondError(w, http.StatusBadRequest, "invalid_status", "status must be pending, approved, or rejected")
		return
	}

	userID := auth.ContextIdentity(r.Context()).UserID
	if userID == "" {
		respondError(w, http.StatusUnauthorized, "unauthorized", "user id required")
		return
	}

	result, err := h.usecase.UpsertSignoff(r.Context(), findingID, userID, req.Status, req.Comment)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", "finding not found")
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this finding")
		default:
			slog.Error("upsert signoff", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		}
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) GetSignoff(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}
	result, err := h.usecase.GetSignoff(r.Context(), findingID)
	if err != nil {
		slog.Error("get signoff", "error", err)
		respondError(w, http.StatusNotFound, "not_found", "signoff not found")
		return
	}
	respondJSON(w, http.StatusOK, result)
}
