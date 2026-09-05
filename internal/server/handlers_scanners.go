package server

import "net/http"

// ListScanners serves the deterministic scanner capability list. The route
// lives under the authenticated API group; the endpoint is capability
// discovery for compile-time plugins, never runtime code loading.
func (h *Handler) ListScanners(w http.ResponseWriter, r *http.Request) {
	scanners := h.usecase.ListScanners()
	respondJSON(w, http.StatusOK, scanners)
}
