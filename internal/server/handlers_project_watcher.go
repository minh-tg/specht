package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"log"
	"math"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/usecase"
)

func (h *Handler) respondProjectWatcherError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, usecase.ErrProjectAccessDenied):
		h.respondProjectAccessError(w, r, errProjectAccessDenied)
	case errors.Is(err, usecase.ErrInvalidWatcherSettings):
		respondError(w, http.StatusBadRequest, "invalid_watcher_settings", err.Error())
	default:
		log.Printf("project watcher %s: %v", op, err)
		respondError(w, http.StatusInternalServerError, "internal_error", "internal server error")
	}
}

// GetProjectWatcher returns a project's watcher settings and status.
func (h *Handler) GetProjectWatcher(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	resp, err := h.usecase.GetProjectWatcher(r.Context(), slug)
	if err != nil {
		h.respondProjectWatcherError(w, r, "get", err)
		return
	}
	respondJSON(w, http.StatusOK, resp)
}

// parseWatcherSettings reads the PUT body. An absent field stays unchanged,
// and interval_seconds set to null returns the interval to its default.
func parseWatcherSettings(raw map[string]json.RawMessage) (usecase.WatcherSettingsInput, error) {
	var in usecase.WatcherSettingsInput
	for key, value := range raw {
		switch key {
		case "enabled":
			var enabled bool
			if err := json.Unmarshal(value, &enabled); err != nil {
				return in, errors.New("enabled must be true or false")
			}
			in.Enabled = &enabled
		case "interval_seconds":
			if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
				in.ResetInterval = true
				continue
			}
			var seconds int64
			if err := json.Unmarshal(value, &seconds); err != nil || seconds < 0 || seconds > math.MaxInt32 {
				return in, errors.New("interval_seconds must be a whole number of seconds, or null for the default")
			}
			s := int32(seconds)
			in.IntervalSeconds = &s
		default:
			return in, errors.New("unknown field " + key + "; use enabled and interval_seconds")
		}
	}
	return in, nil
}

// UpdateProjectWatcher changes a project's watcher settings. Project admin only.
func (h *Handler) UpdateProjectWatcher(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	var raw map[string]json.RawMessage
	if !decodeJSONBody(w, r, &raw, maxJSONBodyBytes, "invalid_json", projectsMsgInvalidBody) {
		return
	}
	in, err := parseWatcherSettings(raw)
	if err != nil {
		respondError(w, http.StatusBadRequest, "invalid_watcher_settings", err.Error())
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	resp, err := h.usecase.UpdateProjectWatcher(r.Context(), slug, in)
	if err != nil {
		h.respondProjectWatcherError(w, r, "update", err)
		return
	}
	respondJSON(w, http.StatusOK, resp)
	h.audit.HTTP(r, audit.EventUpdateWatcher, audit.OutcomeSuccess, slug, slug, nil)
}
