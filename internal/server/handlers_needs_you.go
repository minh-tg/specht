package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/minh-tg/specht/internal/usecase"
)

// NeedsYou answers what waits on the signed-in person across their projects. It is for a person's
// session: an API key has no person behind it, so it gets 403 from the session guard.
func (h *Handler) NeedsYou(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	resp, err := h.usecase.GetNeedsYou(r.Context())
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondError(w, http.StatusForbidden, "project_access_denied", "this needs a signed-in person")
			return
		}
		slog.Error("needs you", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not list what needs you")
		return
	}
	respondJSON(w, http.StatusOK, resp)
}
