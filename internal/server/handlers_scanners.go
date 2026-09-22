package server

import (
	"net/http"

	"github.com/minh-tg/specht/internal/auth"
)

// ListScanners serves the deterministic scanner capability list. The route
// lives under the authenticated API group; the endpoint is capability
// discovery for compile-time plugins, never runtime code loading. It is
// restricted to admin session users: the route-level RequireRole wrap cannot
// reject API keys (they bypass role checks by design), so project-scoped API
// keys and non-admin session users are denied here as well.
func (h *Handler) ListScanners(w http.ResponseWriter, r *http.Request) {
	ident := auth.ContextIdentity(r.Context())
	if ident == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	if ident.IsAPIKey || ident.Role != auth.RoleAdmin {
		respondError(w, http.StatusForbidden, "insufficient_role", "requires admin role")
		return
	}
	scanners := h.usecase.ListScanners()
	respondJSON(w, http.StatusOK, scanners)
}
