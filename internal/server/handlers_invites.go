package server

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/usecase"
)

const invitesMsgInvalidBody = "invalid request body"

// respondInviteError maps invite errors to responses. A dead link answers 404
// whatever killed it, so the response cannot be used to probe links.
func (h *Handler) respondInviteError(w http.ResponseWriter, r *http.Request, op string, err error) {
	switch {
	case errors.Is(err, usecase.ErrProjectAccessDenied):
		h.respondProjectAccessError(w, r, errProjectAccessDenied)
	case errors.Is(err, usecase.ErrInviteNotFound):
		respondError(w, http.StatusNotFound, "not_found", "invite not found")
	case errors.Is(err, usecase.ErrInviteEmailMismatch):
		respondError(w, http.StatusForbidden, "invite_email_mismatch", "this invite is for another email address")
	case errors.Is(err, usecase.ErrInvalidInviteRole):
		respondError(w, http.StatusBadRequest, "invalid_invite_role", err.Error())
	case errors.Is(err, usecase.ErrInvalidInviteInput):
		respondError(w, http.StatusBadRequest, "invalid_invite", err.Error())
	case errors.Is(err, usecase.ErrInvalidID):
		respondError(w, http.StatusBadRequest, "invalid_id", "invalid invite id format")
	case errors.Is(err, usecase.ErrTooManyInvites):
		respondError(w, http.StatusConflict, "too_many_invites", "this project has too many open invites; revoke some first")
	case errors.Is(err, usecase.ErrInvalidCredentialInput):
		respondError(w, http.StatusBadRequest, "invalid_credentials", err.Error())
	case errors.Is(err, usecase.ErrRegistrationFailed):
		// Same answer as registration, so a link cannot reveal which
		// addresses already have an account.
		respondError(w, http.StatusUnprocessableEntity, "registration_failed", "registration failed")
	default:
		slog.Error("invite", "op", op, "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not complete the request")
	}
}

func (h *Handler) CreateInvite(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	var req struct {
		Role          string `json:"role"`
		Email         string `json:"email"`
		ExpiresInDays int    `json:"expires_in_days"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", invitesMsgInvalidBody) {
		return
	}
	if req.Role == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "role is required")
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	invite, err := h.usecase.CreateInvite(r.Context(), slug, usecase.CreateInviteInput{
		Role: req.Role, Email: req.Email, ExpiresInDays: req.ExpiresInDays,
	})
	if err != nil {
		h.respondInviteError(w, r, "create", err)
		return
	}
	// The link is shown once; it never reaches a response cache.
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusCreated, invite)
	h.audit.HTTP(r, audit.EventCreateInvite, audit.OutcomeSuccess, slug, invite.ID, nil)
}

func (h *Handler) ListInvites(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	invites, err := h.usecase.ListInvites(r.Context(), slug)
	if err != nil {
		h.respondInviteError(w, r, "list", err)
		return
	}
	respondJSON(w, http.StatusOK, invites)
}

func (h *Handler) RevokeInvite(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	id := chi.URLParam(r, "id")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	if _, err := h.usecase.RevokeInvite(r.Context(), slug, id); err != nil {
		h.respondInviteError(w, r, "revoke", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
	h.audit.HTTP(r, audit.EventRevokeInvite, audit.OutcomeSuccess, slug, id, nil)
}

func (h *Handler) LookupInvite(w http.ResponseWriter, r *http.Request) {
	view, err := h.usecase.LookupInvite(r.Context(), chi.URLParam(r, "token"))
	if err != nil {
		h.respondInviteError(w, r, "lookup", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusOK, view)
}

func (h *Handler) AcceptInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", invitesMsgInvalidBody) {
		return
	}
	resp, err := h.usecase.AcceptInvite(r.Context(), chi.URLParam(r, "token"), usecase.AcceptInviteInput{
		Email: req.Email, Password: req.Password, DisplayName: req.DisplayName,
	})
	if err != nil {
		h.respondInviteError(w, r, "accept", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	respondJSON(w, http.StatusCreated, resp)
	h.audit.HTTP(r, audit.EventAcceptInvite, audit.OutcomeSuccess, resp.ProjectSlug, resp.UserID, nil)
}

func (h *Handler) JoinInvite(w http.ResponseWriter, r *http.Request) {
	resp, err := h.usecase.JoinInvite(r.Context(), chi.URLParam(r, "token"))
	if err != nil {
		h.respondInviteError(w, r, "join", err)
		return
	}
	respondJSON(w, http.StatusOK, resp)
	h.audit.HTTP(r, audit.EventAcceptInvite, audit.OutcomeSuccess, resp.ProjectSlug, "", nil)
}
