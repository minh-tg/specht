package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/minh-tg/specht/internal/usecase"
)

// suggestProjectMembers answers GET /api/v1/projects/{slug}/member-suggestions
// with people a project manager may add. registrationOpen comes from the same
// router setting the capabilities endpoint reports, so the two always agree.
//
// Accepted residual risk: a project manager can walk the user directory by
// extending prefixes one letter at a time. The 3-character minimum, the cap of
// 8 results and the per-user rate limit on the route (30 a minute, burst 10)
// bound that to a slow crawl, and a manager can already add anyone whose exact
// address they know. Keystrokes are not written to the audit trail.
func (h *Handler) suggestProjectMembers(registrationOpen bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		slug := chi.URLParam(r, "slug")
		// The same 404/403 split as every other project route, before the
		// manager check, so a missing project looks the same here as there.
		if err := h.enforceProjectAccess(r, slug); err != nil {
			h.respondProjectAccessError(w, r, err)
			return
		}
		suggestions, err := h.usecase.SuggestProjectMembers(r.Context(), slug, r.URL.Query().Get("q"), registrationOpen)
		switch {
		case err == nil:
			respondJSON(w, http.StatusOK, suggestions)
		case errors.Is(err, usecase.ErrSuggestionQueryTooLong), errors.Is(err, usecase.ErrSuggestionQueryInvalid):
			respondError(w, http.StatusBadRequest, "invalid_query", err.Error())
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondAccessDenied(w, r, "project")
		default:
			slog.Error("member suggestions failed", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", "could not suggest members")
		}
	}
}
