package server

import (
	"log/slog"
	"net/http"

	"github.com/minh-tg/specht/internal/auth"
)

// GetWatcherStatus reports the CVE watcher daemon's health:
// last successful/attempted poll, last error, consecutive failures. It
// exposes global daemon state, so it is restricted to admin session users.
// The route-level RequireRole wrap cannot reject API keys (they bypass role
// checks by design), so project-scoped API keys and non-admin session users
// are denied here as well.
func (h *Handler) GetWatcherStatus(w http.ResponseWriter, r *http.Request) {
	ident := auth.ContextIdentity(r.Context())
	if ident == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	if ident.IsAPIKey || ident.Role != auth.RoleAdmin {
		respondError(w, http.StatusForbidden, "insufficient_role", "requires admin role")
		return
	}
	status, err := h.usecase.GetWatcherStatus(r.Context())
	if err != nil {
		slog.Error("get watcher status", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not get watcher status")
		return
	}
	respondJSON(w, http.StatusOK, status)
}
