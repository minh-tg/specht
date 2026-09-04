package server

import (
	"log/slog"
	"net/http"
)

// GetWatcherStatus reports the CVE watcher daemon's health:
// last successful/attempted poll, last error, consecutive failures.
func (h *Handler) GetWatcherStatus(w http.ResponseWriter, r *http.Request) {
	status, err := h.usecase.GetWatcherStatus(r.Context())
	if err != nil {
		slog.Error("get watcher status", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	respondJSON(w, http.StatusOK, status)
}
