package server

import (
	"errors"
	"log"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
)

const (
	projectsMsgInvalidBody  = "invalid request body"
	projectsMsgAccessDenied = "project access denied"
	projectsMsgNotFound     = "project not found"
)

func (h *Handler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Slug        string `json:"slug"`
		Description string `json:"description,omitempty"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", projectsMsgInvalidBody) {
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
		if errors.Is(err, usecase.ErrSlugTaken) {
			respondError(w, http.StatusConflict, "slug_taken", "project slug already exists")
			return
		}
		respondError(w, http.StatusInternalServerError, "creation_failed", "could not create project")
		return
	}
	respondJSON(w, http.StatusCreated, result)
	h.audit.HTTP(r, audit.EventCreateProject, audit.OutcomeSuccess, req.Slug, req.Slug, nil)
}

func (h *Handler) ListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := h.usecase.ListProjects(r.Context())
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondError(w, http.StatusForbidden, "project_access_denied", projectsMsgAccessDenied)
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
		h.respondProjectAccessError(w, r, err)
		return
	}
	project, err := h.usecase.GetProject(r.Context(), slug)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", projectsMsgNotFound)
		return
	}
	respondJSON(w, http.StatusOK, project)
}

func (h *Handler) UpdateProject(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	var req struct {
		Name        *string `json:"name"`
		Description *string `json:"description"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", projectsMsgInvalidBody) {
		return
	}
	if req.Name == nil && req.Description == nil {
		respondError(w, http.StatusBadRequest, "missing_field", "name or description is required")
		return
	}
	project, err := h.usecase.UpdateProject(r.Context(), slug, req.Name, req.Description)
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondError(w, http.StatusForbidden, "project_access_denied", projectsMsgAccessDenied)
			return
		}
		respondError(w, http.StatusNotFound, "not_found", projectsMsgNotFound)
		return
	}
	respondJSON(w, http.StatusOK, project)
	h.audit.HTTP(r, audit.EventUpdateProject, audit.OutcomeSuccess, slug, slug, nil)
}

func (h *Handler) DeleteProject(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	project, err := h.usecase.DeleteProject(r.Context(), slug)
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondError(w, http.StatusForbidden, "project_access_denied", projectsMsgAccessDenied)
			return
		}
		respondError(w, http.StatusNotFound, "not_found", projectsMsgNotFound)
		return
	}
	respondJSON(w, http.StatusOK, project)
	h.audit.HTTP(r, audit.EventDeleteProject, audit.OutcomeSuccess, slug, slug, nil)
}

func (h *Handler) ListReports(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	limit := parseIntParam(r, "limit", 20)
	offset := parseOffsetParam(r, "offset", 0)

	reports, err := h.usecase.ListReports(r.Context(), slug, limit, offset)
	if err != nil {
		log.Printf("list reports: %v", err)
		if errors.Is(err, port.ErrNotFound) {
			respondError(w, http.StatusNotFound, "not_found", projectsMsgNotFound)
		} else {
			respondError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
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
		h.respondProjectAccessError(w, r, err)
		return
	}
	members, err := h.usecase.ListProjectMembers(r.Context(), slug)
	if err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", projectsMsgAccessDenied)
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
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", projectsMsgInvalidBody) {
		return
	}
	if req.UserID == "" || req.Role == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "user_id and role are required")
		return
	}
	// Stop outsiders here so the specific errors below cannot reveal whether a
	// project or a user exists to someone with no access to it.
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	member, err := h.usecase.AddProjectMember(r.Context(), slug, req.UserID, req.Role)
	if err != nil {
		respondMemberError(w, err)
		return
	}
	respondJSON(w, http.StatusCreated, member)
}

// respondMemberError maps a membership usecase error to its HTTP response.
// An unrecognised error is a server fault: it is logged and reported as such
// instead of masquerading as a permission problem.
func respondMemberError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, usecase.ErrInvalidID):
		respondError(w, http.StatusBadRequest, "invalid_id", err.Error())
	case errors.Is(err, usecase.ErrInvalidMemberRole):
		respondError(w, http.StatusBadRequest, "invalid_role", err.Error())
	case errors.Is(err, usecase.ErrLastAdminForbidden):
		respondError(w, http.StatusBadRequest, "last_admin", err.Error())
	case errors.Is(err, usecase.ErrMemberNotFound):
		respondError(w, http.StatusNotFound, "member_not_found", "project member not found")
	case errors.Is(err, usecase.ErrMemberUserNotFound):
		respondError(w, http.StatusNotFound, "user_not_found", "user not found")
	case errors.Is(err, usecase.ErrProjectAccessDenied):
		respondError(w, http.StatusForbidden, "project_access_denied", projectsMsgAccessDenied)
	default:
		slog.Error("project membership change failed", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not update project members")
	}
}

func (h *Handler) RemoveProjectMember(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	userID := chi.URLParam(r, "userID")
	if slug == "" || userID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "project slug and user id are required")
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	if err := h.usecase.RemoveProjectMember(r.Context(), slug, userID); err != nil {
		respondMemberError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
