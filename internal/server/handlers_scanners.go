package server

import "net/http"

// ListScanners serves the deterministic scanner capability list. The route
// sits behind RequireSession, so any signed-in user can read it while project
// API keys are refused. The endpoint is capability discovery for compile-time
// plugins, never runtime code loading, and the catalog holds no secrets.
func (h *Handler) ListScanners(w http.ResponseWriter, r *http.Request) {
	scanners := h.usecase.ListScanners()
	respondJSON(w, http.StatusOK, scanners)
}
