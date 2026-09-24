package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

const (
	assessMsgFindingIDRequired   = "finding id is required"
	assessMsgInvalidBody         = "invalid request body"
	assessMsgFindingNotFound     = "finding not found"
	assessMsgFindingAccessDenied = "API key does not have access to this finding"
)

func (h *Handler) CreateEvidence(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", assessMsgFindingIDRequired)
		return
	}
	var req struct {
		Type        string `json:"type"`
		URL         string `json:"url"`
		Description string `json:"description"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", assessMsgInvalidBody) {
		return
	}
	if req.Type == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "type is required")
		return
	}

	var userID string
	if ident := auth.ContextIdentity(r.Context()); ident != nil {
		userID = ident.UserID
	}

	result, err := h.usecase.CreateEvidence(r.Context(), findingID, userID, req.Type, req.URL, req.Description)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", assessMsgFindingNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", assessMsgFindingAccessDenied)
		case errors.Is(err, usecase.ErrInvalidFindingID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		case errors.Is(err, usecase.ErrInvalidEvidenceType):
			respondError(w, http.StatusBadRequest, "invalid_type",
				"type must be screenshot, log, reference, or automated")
		default:
			slog.Error("create evidence", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", "could not create evidence")
		}
		return
	}
	respondJSON(w, http.StatusCreated, result)
}

func (h *Handler) ListEvidence(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", assessMsgFindingIDRequired)
		return
	}
	result, err := h.usecase.ListEvidence(r.Context(), findingID)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", assessMsgFindingNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", assessMsgFindingAccessDenied)
		default:
			slog.Error("list evidence", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", "could not list evidence")
		}
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
		switch {
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", assessMsgFindingAccessDenied)
		case errors.Is(err, usecase.ErrInvalidID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid evidence id format")
		case errors.Is(err, usecase.ErrEvidenceNotFound):
			respondError(w, http.StatusNotFound, "not_found", "evidence not found")
		default:
			slog.Error("delete evidence", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", "could not delete evidence")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) UpsertReachability(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", assessMsgFindingIDRequired)
		return
	}
	var req struct {
		State    string `json:"state"`
		Evidence string `json:"evidence"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", assessMsgInvalidBody) {
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
			respondError(w, http.StatusBadRequest, "invalid_state", "invalid reachability state")
		case errors.Is(err, usecase.ErrInvalidFindingID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", assessMsgFindingNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", assessMsgFindingAccessDenied)
		default:
			slog.Error("upsert reachability", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", "could not update reachability state")
		}
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) ListReachability(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", assessMsgFindingIDRequired)
		return
	}
	result, err := h.usecase.ListReachability(r.Context(), findingID)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidFindingID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", assessMsgFindingNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", assessMsgFindingAccessDenied)
		default:
			slog.Error("list reachability", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", "could not list reachability states")
		}
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) UpsertSignoff(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", assessMsgFindingIDRequired)
		return
	}
	var req struct {
		Status  string `json:"status"`
		Comment string `json:"comment"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", assessMsgInvalidBody) {
		return
	}
	if req.Status != "approved" && req.Status != "rejected" && req.Status != "pending" {
		respondError(w, http.StatusBadRequest, "invalid_status", "status must be pending, approved, or rejected")
		return
	}

	ident := auth.ContextIdentity(r.Context())
	if ident == nil || ident.UserID == "" {
		respondError(w, http.StatusUnauthorized, "unauthorized", "user id required")
		return
	}
	userID := ident.UserID

	result, err := h.usecase.UpsertSignoff(r.Context(), findingID, userID, req.Status, req.Comment)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", assessMsgFindingNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", assessMsgFindingAccessDenied)
		case errors.Is(err, usecase.ErrInvalidFindingID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		default:
			slog.Error("upsert signoff", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", "could not update signoff")
		}
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) GetSignoff(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "findingID")
	if findingID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", assessMsgFindingIDRequired)
		return
	}
	result, err := h.usecase.GetSignoff(r.Context(), findingID)
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondError(w, http.StatusForbidden, "project_access_denied", assessMsgFindingAccessDenied)
		} else {
			slog.Error("get signoff", "error", err)
			respondError(w, http.StatusNotFound, "not_found", "signoff not found")
		}
		return
	}
	respondJSON(w, http.StatusOK, result)
}
