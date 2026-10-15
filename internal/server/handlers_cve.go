package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/usecase"
)

// CVEUsecases serves the CVE evaluation details of a finding.
type CVEUsecases interface {
	GetFindingCVE(ctx context.Context, findingID string) (*usecase.CVEDetailResponse, error)
}

// GetFindingCVE handles GET /api/v1/findings/{id}/cve. It answers from the
// scan reports, the intel feeds and the provider cache; a provider fetch, when
// one is needed, runs in the background and never delays or fails this read.
func (h *Handler) GetFindingCVE(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := uuid.Parse(id); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		return
	}
	detail, err := h.usecase.GetFindingCVE(r.Context(), id)
	switch {
	case err == nil:
		respondJSON(w, http.StatusOK, detail)
	case errors.Is(err, usecase.ErrProjectAccessDenied):
		respondAccessDenied(w, r, "finding")
	case errors.Is(err, usecase.ErrFindingNotFound):
		respondError(w, http.StatusNotFound, "not_found", "finding not found")
	case errors.Is(err, usecase.ErrNotCVE):
		respondError(w, http.StatusNotFound, "not_cve", "This finding has no CVE identifier, so there are no CVE details to show.")
	default:
		slog.Error("get finding cve details", "finding_id", id, "error", err)
		respondError(w, http.StatusInternalServerError, "cve_detail_failed", "could not load the CVE details")
	}
}
