package server

import (
	"errors"
	"log"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/xMinhx/specht/internal/audit"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/usecase"
)

func (h *Handler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Slug        string `json:"slug"`
		Description string `json:"description,omitempty"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", "invalid request body") {
		return
	}
	if req.Name == "" || req.Slug == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "name and slug are required")
		return
	}

	ident := auth.ContextIdentity(r.Context())
	if ident == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	result, err := h.usecase.CreateProject(r.Context(), req.Name, req.Slug, req.Description, ident.UserID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "creation_failed", "could not create project")
		return
	}
	respondJSON(w, http.StatusCreated, result)
	h.audit.HTTP(r, audit.EventCreateProject, audit.OutcomeSuccess, "", req.Slug, nil)
}

func (h *Handler) ListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := h.usecase.ListProjects(r.Context())
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondError(w, http.StatusForbidden, "project_access_denied", "project access denied")
			return
		}
		slog.Error("list projects", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "failed to list projects")
		return
	}
	respondJSON(w, http.StatusOK, projects)
}

func (h *Handler) GetProject(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}
	project, err := h.usecase.GetProject(r.Context(), slug)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	respondJSON(w, http.StatusOK, project)
}

func (h *Handler) ListReports(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}
	limit := parseIntParam(r, "limit", 20)
	offset := parseIntParam(r, "offset", 0)

	reports, err := h.usecase.ListReports(r.Context(), slug, limit, offset)
	if err != nil {
		log.Printf("list reports: %v", err)
		respondError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	respondJSON(w, http.StatusOK, reports)
}

func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	if _, err := uuid.Parse(idStr); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_id", "invalid report id")
		return
	}

	report, err := h.usecase.GetReport(r.Context(), idStr)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", "report not found")
		return
	}
	respondJSON(w, http.StatusOK, report)
}

func (h *Handler) ListProjectMembers(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}
	members, err := h.usecase.ListProjectMembers(r.Context(), slug)
	if err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", "project access denied")
		return
	}
	respondJSON(w, http.StatusOK, members)
}

func (h *Handler) AddProjectMember(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", "invalid request body") {
		return
	}
	if req.UserID == "" || req.Role == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "user_id and role are required")
		return
	}
	member, err := h.usecase.AddProjectMember(r.Context(), slug, req.UserID, req.Role)
	if err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", "project access denied")
		return
	}
	respondJSON(w, http.StatusCreated, member)
}
