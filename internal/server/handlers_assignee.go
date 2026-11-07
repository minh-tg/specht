package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/minh-tg/specht/internal/usecase"
)

// AssignFinding sets who owns a finding. A null or empty user_id clears it.
func (h *Handler) AssignFinding(w http.ResponseWriter, r *http.Request) {
	var req struct {
		UserID string `json:"user_id"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", triageMsgInvalidBody) {
		return
	}
	assignee, err := h.usecase.AssignFinding(r.Context(), chi.URLParam(r, "id"), req.UserID)
	switch {
	case err == nil:
		respondJSON(w, http.StatusOK, map[string]any{"assignee": assignee})
	case errors.Is(err, usecase.ErrInvalidFindingID):
		respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id")
	case errors.Is(err, usecase.ErrFindingNotFound):
		respondError(w, http.StatusNotFound, "not_found", "finding not found")
	case errors.Is(err, usecase.ErrAssigneeNotMember):
		respondError(w, http.StatusBadRequest, "assignee_not_member", err.Error())
	case errors.Is(err, usecase.ErrProjectAccessDenied):
		respondAccessDenied(w, r, "finding")
	default:
		slog.Error("assign finding", "error", err)
		respondError(w, http.StatusInternalServerError, "assign_failed", "could not assign the finding")
	}
}
