package server

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xMinhx/specht/internal/audit"
	"github.com/xMinhx/specht/internal/auth"
)

// authMsgInvalidBody is the user-facing message for malformed auth payloads.
const authMsgInvalidBody = "invalid request body"

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
		return
	}

	result, err := h.usecase.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		// M8: never echo the underlying error — a duplicate email must be
		// indistinguishable from any other registration failure, or this
		// endpoint becomes an account-enumeration oracle. Detail goes to the
		// server log only.
		slog.Error("register failed", "email", req.Email, "error", err)
		respondError(w, http.StatusUnprocessableEntity, "registration_failed", "registration failed")
		h.audit.HTTP(r, audit.EventRegister, audit.OutcomeFailure, "", req.Email, err)
		return
	}
	respondJSON(w, http.StatusCreated, result)
	h.audit.HTTP(r, audit.EventRegister, audit.OutcomeSuccess, "", req.Email, nil)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
		return
	}

	result, err := h.usecase.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "login_failed", "invalid email or password")
		h.audit.HTTP(r, audit.EventLogin, audit.OutcomeFailure, "", req.Email, err)
		return
	}
	respondJSON(w, http.StatusOK, result)
	h.audit.HTTP(r, audit.EventLogin, audit.OutcomeSuccess, "", req.Email, nil)
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
		return
	}

	result, err := h.usecase.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		// The refresh-token failure mode (invalid, revoked, expired, or an
		// internal store error) is deliberately indistinguishable to clients:
		// the only actionable response is to re-authenticate. Detail is logged.
		slog.Error("refresh", "error", err)
		respondError(w, http.StatusUnauthorized, "refresh_failed", "invalid or expired refresh token")
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
		return
	}

	if err := h.usecase.Logout(r.Context(), req.RefreshToken); err != nil {
		slog.Error("logout", "error", err)
		respondError(w, http.StatusInternalServerError, "logout_failed", "logout failed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
	h.audit.HTTP(r, audit.EventLogout, audit.OutcomeSuccess, "", "", nil)
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	ident := auth.ContextIdentity(r.Context())
	if ident == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized", "not authenticated")
		return
	}

	profile, err := h.usecase.GetProfile(r.Context(), ident.UserID)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	respondJSON(w, http.StatusOK, profile)
}

func (h *Handler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DisplayName *string `json:"display_name"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
		return
	}

	ident := auth.ContextIdentity(r.Context())
	if ident == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized", "not authenticated")
		return
	}

	profile, err := h.usecase.UpdateProfile(r.Context(), ident.UserID, req.DisplayName)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	respondJSON(w, http.StatusOK, profile)
}

func (h *Handler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Project   string `json:"project"`
		Name      string `json:"name"`
		ExpiresAt string `json:"expires_at"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
		return
	}
	if req.Project == "" || req.Name == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "project and name are required")
		return
	}
	var expiresAt *time.Time
	if req.ExpiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid_expires_at", "expires_at must be an RFC3339 timestamp")
			return
		}
		expiresAt = &parsed
	}
	if err := h.enforceProjectAccess(r, req.Project); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}

	ident := auth.ContextIdentity(r.Context())
	if ident == nil || ident.UserID == "" {
		respondError(w, http.StatusUnauthorized, "unauthorized", "user id required")
		return
	}

	result, err := h.usecase.CreateAPIKey(r.Context(), req.Project, req.Name, ident.UserID, expiresAt)
	if err != nil {
		slog.Error("create api key", "project", req.Project, "error", err)
		respondError(w, http.StatusUnprocessableEntity, "create_failed", "could not create API key")
		return
	}
	respondJSON(w, http.StatusCreated, result)
	h.audit.HTTP(r, audit.EventCreateAPIKey, audit.OutcomeSuccess, req.Project, req.Name, nil)
}

func (h *Handler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	if project == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "project query param is required")
		return
	}
	if err := h.enforceProjectAccess(r, project); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}

	keys, err := h.usecase.ListAPIKeys(r.Context(), project)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	respondJSON(w, http.StatusOK, keys)
	h.audit.HTTP(r, audit.EventListAPIKeys, audit.OutcomeSuccess, project, "", nil)
}

func (h *Handler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	keyID := chi.URLParam(r, "id")
	if project == "" || keyID == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "project and key id are required")
		return
	}
	if err := h.enforceProjectAccess(r, project); err != nil {
		h.respondProjectAccessError(w, err)
		return
	}
	if err := h.usecase.RevokeAPIKey(r.Context(), project, keyID); err != nil {
		slog.Error("revoke api key", "project", project, "key_id", keyID, "error", err)
		respondError(w, http.StatusUnprocessableEntity, "revoke_failed", "could not revoke API key")
		return
	}
	w.WriteHeader(http.StatusNoContent)
	h.audit.HTTP(r, audit.EventRevokeAPIKey, audit.OutcomeSuccess, project, keyID, nil)
}
