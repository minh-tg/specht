package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
)

// authMsgInvalidBody is the user-facing message for malformed auth payloads.
const authMsgInvalidBody = "invalid request body"

// errLoginDelayed is the audit reason for a sign-in refused during an
// account's wait.
var errLoginDelayed = errors.New("sign-in refused during the account's wait")

// errPasswordChangeDelayed is the audit reason for a password change refused
// during the account's wait.
var errPasswordChangeDelayed = errors.New("password change refused during the account's wait")

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
		h.audit.HTTP(r, audit.EventRegister, audit.OutcomeFailure, "", auth.MaskEmail(req.Email), err)
		// The password policy refusals and the hidden-character address get
		// their own codes. Register checks the password and the address
		// before it looks the address up, so these answers are the same for
		// a registered address and a new one.
		switch {
		case errors.Is(err, usecase.ErrPasswordTooCommon):
			respondError(w, http.StatusBadRequest, "password_too_common", err.Error())
			return
		case errors.Is(err, usecase.ErrPasswordMatchesAccount):
			respondError(w, http.StatusBadRequest, "password_matches_account", err.Error())
			return
		case errors.Is(err, usecase.ErrInvalidEmailCharacters):
			respondError(w, http.StatusUnprocessableEntity, "invalid_email_characters", err.Error())
			return
		}
		// M8: never echo the underlying error — a duplicate email must be
		// indistinguishable from any other registration failure, or this
		// endpoint becomes an account-enumeration oracle. Detail goes to the
		// server log only.
		slog.Error("register failed", "email", auth.MaskEmail(req.Email), "error", err)
		respondError(w, http.StatusUnprocessableEntity, "registration_failed", "registration failed")
		return
	}
	respondJSON(w, http.StatusCreated, result)
	h.audit.HTTP(r, audit.EventRegister, audit.OutcomeSuccess, "", auth.MaskEmail(req.Email), nil)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
		return
	}

	// An attempt without an email or password never reaches a password
	// check, so it spends nothing from the account's allowance.
	var ticket loginTicket
	email := auth.NormalizeEmail(req.Email)
	if h.loginDelay != nil && email != "" && req.Password != "" {
		var retryAfter time.Duration
		var ok bool
		ticket, retryAfter, ok = h.loginDelay.begin(email)
		if !ok {
			secs := max(int(math.Ceil(retryAfter.Seconds())), 1)
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			respondError(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed sign-in attempts, retry later")
			h.audit.HTTP(r, audit.EventLogin, audit.OutcomeFailure, "", auth.MaskEmail(req.Email), errLoginDelayed)
			return
		}
	}

	result, err := h.usecase.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "login_failed", "invalid email or password")
		h.audit.HTTP(r, audit.EventLogin, audit.OutcomeFailure, "", auth.MaskEmail(req.Email), err)
		return
	}
	if h.loginDelay != nil && ticket.key != "" {
		h.loginDelay.succeed(ticket)
	}
	respondJSON(w, http.StatusOK, result)
	h.audit.HTTP(r, audit.EventLogin, audit.OutcomeSuccess, "", auth.MaskEmail(req.Email), nil)
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
		if errors.Is(err, usecase.ErrRefreshReused) {
			// The token was already spent, so the server revoked the sign-in it
			// belongs to. The client must sign the user out and say why.
			respondError(w, http.StatusUnauthorized, "refresh_reused", "refresh token was already used")
			return
		}
		slog.Error("refresh", "error", err)
		respondError(w, http.StatusUnauthorized, "refresh_failed", "invalid or expired refresh token")
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) SSOExchange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
		return
	}
	if req.Code == "" {
		respondError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	result, err := h.usecase.ExchangeSSOCode(r.Context(), req.Code)
	if err != nil {
		if errors.Is(err, auth.ErrInvalidCredential) {
			respondError(w, http.StatusUnauthorized, "invalid_code", "invalid or expired exchange code")
			return
		}
		slog.Error("sso exchange", "error", err)
		respondError(w, http.StatusInternalServerError, "exchange_failed", "code exchange failed")
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
	// Logout remains usable with only a refresh token, but when a bearer
	// access token is supplied, retire it immediately rather than waiting for
	// its normal expiry.
	if h.revoker != nil {
		if bearer := r.Header.Get("Authorization"); len(bearer) > 7 && strings.EqualFold(bearer[:7], "Bearer ") {
			if err := h.revoker.RevokeTokenContext(r.Context(), strings.TrimSpace(bearer[7:])); err != nil && !errors.Is(err, auth.ErrInvalidCredential) {
				slog.Error("access token revocation failed during logout", "error", err)
				respondError(w, http.StatusInternalServerError, "logout_failed", "logout failed")
				return
			}
		}
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
	if errors.Is(err, usecase.ErrInvalidProfileInput) {
		respondError(w, http.StatusBadRequest, "invalid_display_name", err.Error())
		return
	}
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	respondJSON(w, http.StatusOK, profile)
}

// ChangePassword lets a signed-in person replace their own password. A wrong
// current password answers 400, never 401: the client treats a 401 as an
// expired session and would sign the person out of a form they just mistyped.
func (h *Handler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
		return
	}
	ident := auth.ContextIdentity(r.Context())
	if ident == nil || ident.IsAPIKey {
		respondError(w, http.StatusUnauthorized, "unauthorized", "not authenticated")
		return
	}

	// The current password is a guessable secret, so a stolen access token
	// gets the same per-account allowance as the sign-in form, and both paths
	// draw on one count. The attempt is charged before the check and given
	// back when it succeeds or never reached a password comparison.
	var ticket loginTicket
	if h.loginDelay != nil && req.CurrentPassword != "" {
		key := auth.NormalizeEmail(ident.Email)
		if key == "" {
			key = "user:" + ident.UserID
		}
		var retryAfter time.Duration
		var ok bool
		ticket, retryAfter, ok = h.loginDelay.begin(key)
		if !ok {
			secs := max(int(math.Ceil(retryAfter.Seconds())), 1)
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			respondError(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed password attempts, retry later")
			h.audit.HTTP(r, audit.EventChangePassword, audit.OutcomeFailure, "", ident.UserID, errPasswordChangeDelayed)
			return
		}
	}

	result, err := h.usecase.ChangePassword(r.Context(), ident.UserID, req.CurrentPassword, req.NewPassword)
	if err != nil {
		if h.loginDelay != nil && !errors.Is(err, usecase.ErrWrongPassword) {
			// Only a wrong current password is a failed guess. Every other
			// error was raised before the comparison, or after it passed.
			h.loginDelay.refund(ticket)
		}
		h.audit.HTTP(r, audit.EventChangePassword, audit.OutcomeFailure, "", ident.UserID, err)
		switch {
		case errors.Is(err, usecase.ErrWrongPassword):
			respondError(w, http.StatusBadRequest, "wrong_password", "the current password is not correct")
		case errors.Is(err, usecase.ErrPasswordTooCommon):
			respondError(w, http.StatusBadRequest, "password_too_common", err.Error())
		case errors.Is(err, usecase.ErrPasswordMatchesAccount):
			respondError(w, http.StatusBadRequest, "password_matches_account", err.Error())
		case errors.Is(err, usecase.ErrInvalidCredentialInput):
			respondError(w, http.StatusBadRequest, "invalid_password", err.Error())
		case errors.Is(err, usecase.ErrNoLocalPassword):
			respondError(w, http.StatusConflict, "no_local_password", "this account signs in through your identity provider and has no password to change")
		case errors.Is(err, usecase.ErrAccountChanged):
			respondError(w, http.StatusConflict, "account_changed", "the password was changed, but the account changed right after, so you were signed out; sign in again")
		case errors.Is(err, usecase.ErrInvalidID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid user id")
		default:
			slog.Error("change password", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", "could not change the password")
		}
		return
	}
	if h.loginDelay != nil {
		h.loginDelay.succeed(ticket)
	}
	respondJSON(w, http.StatusOK, result)
	h.audit.HTTP(r, audit.EventChangePassword, audit.OutcomeSuccess, "", ident.UserID, nil)
}

// ListUsers serves the account directory that admin surfaces pick from:
// grant project membership, add a team member. Session admins only — a
// project-scoped key has no business enumerating the organization, and the
// route-level session guard is mirrored here so the handler stays safe if it
// is ever mounted without it.
func (h *Handler) ListUsers(w http.ResponseWriter, r *http.Request) {
	ident := auth.ContextIdentity(r.Context())
	if ident == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
		return
	}
	if ident.IsAPIKey || ident.Role != auth.RoleAdmin {
		respondError(w, http.StatusForbidden, "insufficient_role", "requires admin role")
		return
	}

	users, err := h.usecase.ListUsers(r.Context(), r.URL.Query().Get("email"),
		parseIntParam(r, "limit", 20), parseOffsetParam(r, "offset", 0))
	if err != nil {
		slog.Error("list users", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not list users")
		return
	}
	respondJSON(w, http.StatusOK, users)
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
		h.respondProjectAccessError(w, r, err)
		return
	}

	ident := auth.ContextIdentity(r.Context())
	if ident == nil || ident.UserID == "" {
		respondError(w, http.StatusUnauthorized, "unauthorized", "user id required")
		return
	}

	result, err := h.usecase.CreateAPIKey(r.Context(), req.Project, req.Name, ident.UserID, expiresAt)
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			h.respondProjectAccessError(w, r, errProjectAccessDenied)
			return
		}
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
		h.respondProjectAccessError(w, r, err)
		return
	}

	keys, err := h.usecase.ListAPIKeys(r.Context(), project)
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			h.respondProjectAccessError(w, r, errProjectAccessDenied)
			return
		}
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
		h.respondProjectAccessError(w, r, err)
		return
	}
	if err := h.usecase.RevokeAPIKey(r.Context(), project, keyID); err != nil {
		switch {
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			h.respondProjectAccessError(w, r, errProjectAccessDenied)
		case errors.Is(err, usecase.ErrInvalidID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid key id format")
		case errors.Is(err, usecase.ErrAPIKeyNotFound):
			respondError(w, http.StatusNotFound, "not_found", "API key not found")
		default:
			slog.Error("revoke api key", "project", project, "key_id", keyID, "error", err)
			respondError(w, http.StatusUnprocessableEntity, "revoke_failed", "could not revoke API key")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
	h.audit.HTTP(r, audit.EventRevokeAPIKey, audit.OutcomeSuccess, project, keyID, nil)
}

// respondUserAdminError maps the user admin errors to responses. It returns
// false for an error it does not recognise.
func respondUserAdminError(w http.ResponseWriter, err error) bool {
	var soleAdmin *usecase.SoleProjectAdminError
	switch {
	case errors.As(err, &soleAdmin):
		respondError(w, http.StatusConflict, "sole_project_admin",
			fmt.Sprintf("this account is the only active admin of: %s; add another admin to those projects first, or send force to deactivate anyway", strings.Join(soleAdmin.Projects, ", ")))
	case errors.Is(err, usecase.ErrProjectAccessDenied):
		respondError(w, http.StatusForbidden, "insufficient_role", "requires admin role")
	case errors.Is(err, usecase.ErrInvalidID):
		respondError(w, http.StatusBadRequest, "invalid_id", "invalid user id")
	case errors.Is(err, usecase.ErrInvalidGlobalRole):
		respondError(w, http.StatusBadRequest, "invalid_role", err.Error())
	case errors.Is(err, usecase.ErrLastGlobalAdmin):
		respondError(w, http.StatusConflict, "last_admin", "this is the last active admin")
	case errors.Is(err, usecase.ErrCannotDeactivateSelf):
		respondError(w, http.StatusConflict, "cannot_deactivate_self", err.Error())
	case errors.Is(err, usecase.ErrSystemAccount):
		respondError(w, http.StatusConflict, "system_account", err.Error())
	case errors.Is(err, usecase.ErrNoLocalPassword):
		respondError(w, http.StatusConflict, "no_local_password", "this account signs in through an identity provider and has no password to reset")
	case errors.Is(err, usecase.ErrAccountDeactivated):
		respondError(w, http.StatusConflict, "account_deactivated", "reactivate the account before issuing a reset link")
	case errors.Is(err, usecase.ErrAccountNotFound):
		respondError(w, http.StatusNotFound, "not_found", "user not found")
	case errors.Is(err, port.ErrNotFound):
		respondError(w, http.StatusNotFound, "not_found", "user not found")
	default:
		return false
	}
	return true
}

// CreatePasswordResetLink issues a one-time link an administrator hands to a person who is locked
// out. The token is in the response only; it is not stored and cannot be shown again.
func (h *Handler) CreatePasswordResetLink(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	link, err := h.usecase.CreatePasswordResetLink(r.Context(), id)
	if err != nil {
		h.audit.HTTP(r, audit.EventResetLink, audit.OutcomeFailure, "", id, err)
		if respondUserAdminError(w, err) {
			return
		}
		slog.Error("create password reset link", "user_id", id, "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not create the reset link")
		return
	}
	respondJSON(w, http.StatusCreated, link)
	h.audit.HTTP(r, audit.EventResetLink, audit.OutcomeSuccess, "", id, nil)
}

// ResetPassword sets a new password from a reset link. It is public: the link is the credential.
// Every dead link answers alike.
func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token    string `json:"token"`
		Password string `json:"password"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
		return
	}
	if err := h.usecase.RedeemPasswordReset(r.Context(), req.Token, req.Password); err != nil {
		h.audit.HTTP(r, audit.EventResetPassword, audit.OutcomeFailure, "", "", err)
		switch {
		case errors.Is(err, usecase.ErrResetLinkInvalid):
			respondError(w, http.StatusBadRequest, "reset_link_invalid", "this reset link is not valid or has expired")
		case errors.Is(err, usecase.ErrPasswordTooCommon):
			respondError(w, http.StatusBadRequest, "password_too_common", err.Error())
		case errors.Is(err, usecase.ErrPasswordMatchesAccount):
			respondError(w, http.StatusBadRequest, "password_matches_account", err.Error())
		case errors.Is(err, usecase.ErrInvalidCredentialInput):
			respondError(w, http.StatusBadRequest, "invalid_password", err.Error())
		default:
			slog.Error("reset password", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", "could not reset the password")
		}
		return
	}
	w.WriteHeader(http.StatusNoContent)
	h.audit.HTTP(r, audit.EventResetPassword, audit.OutcomeSuccess, "", "", nil)
}

// ChangeUserRole sets an account's global role.
func (h *Handler) ChangeUserRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req struct {
		Role string `json:"role"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
		return
	}
	profile, err := h.usecase.ChangeUserRole(r.Context(), id, req.Role)
	if err != nil {
		if respondUserAdminError(w, err) {
			return
		}
		slog.Error("change user role", "user_id", id, "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not change the role")
		return
	}
	respondJSON(w, http.StatusOK, profile)
	h.audit.HTTP(r, audit.EventChangeUserRole, audit.OutcomeSuccess, "", id, nil)
}

// DeactivateUser ends an account's access without deleting it.
func (h *Handler) DeactivateUser(w http.ResponseWriter, r *http.Request) {
	h.setUserActive(w, r, false)
}

// ReactivateUser lets a deactivated account sign in again.
func (h *Handler) ReactivateUser(w http.ResponseWriter, r *http.Request) {
	h.setUserActive(w, r, true)
}

func (h *Handler) setUserActive(w http.ResponseWriter, r *http.Request, active bool) {
	id := chi.URLParam(r, "id")
	var req struct {
		Force bool `json:"force"`
	}
	// The body is optional: only a deactivation reads it, for the confirmation.
	if !active && r.ContentLength != 0 {
		if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
			return
		}
	}
	var (
		profile     *usecase.UserProfile
		revokedKeys []usecase.RevokedAPIKey
		err         error
		event       = audit.EventReactivateUser
	)
	if active {
		profile, err = h.usecase.ReactivateUser(r.Context(), id)
	} else {
		event = audit.EventDeactivateUser
		profile, revokedKeys, err = h.usecase.DeactivateUser(r.Context(), id, req.Force)
	}
	if err != nil {
		if respondUserAdminError(w, err) {
			return
		}
		slog.Error("set user active", "user_id", id, "active", active, "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not update the account")
		return
	}
	respondJSON(w, http.StatusOK, profile)
	h.audit.HTTP(r, event, audit.OutcomeSuccess, "", id, nil)
	// Keys that went with the account get the line a manual revoke would.
	for _, key := range revokedKeys {
		h.audit.HTTP(r, audit.EventRevokeAPIKey, audit.OutcomeSuccess, key.ProjectSlug, key.ID, nil)
	}
}

// Setup creates the first admin on a fresh server. It is public, so it works
// only while no admin exists and only with the token the server showed at
// startup; afterwards the route answers 404 as if it were not there.
func (h *Handler) Setup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", authMsgInvalidBody) {
		return
	}
	resp, err := h.usecase.Setup(r.Context(), usecase.SetupInput{
		Token: req.Token, Email: req.Email, Password: req.Password, DisplayName: req.DisplayName,
	})
	switch {
	case err == nil:
	case errors.Is(err, usecase.ErrSetupClosed):
		respondError(w, http.StatusNotFound, "not_found", "not found")
		return
	case errors.Is(err, usecase.ErrInvalidSetupToken):
		respondError(w, http.StatusForbidden, "invalid_setup_token", "the setup token is wrong")
		return
	case errors.Is(err, usecase.ErrSetupEmailTaken):
		respondError(w, http.StatusConflict, "email_in_use", err.Error())
		return
	case errors.Is(err, usecase.ErrPasswordTooCommon):
		respondError(w, http.StatusBadRequest, "password_too_common", err.Error())
		return
	case errors.Is(err, usecase.ErrPasswordMatchesAccount):
		respondError(w, http.StatusBadRequest, "password_matches_account", err.Error())
		return
	case errors.Is(err, usecase.ErrInvalidEmailCharacters):
		respondError(w, http.StatusBadRequest, "invalid_email_characters", err.Error())
		return
	case errors.Is(err, usecase.ErrInvalidCredentialInput):
		respondError(w, http.StatusBadRequest, "invalid_credentials", err.Error())
		return
	default:
		slog.Error("setup", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not complete setup")
		return
	}
	respondJSON(w, http.StatusCreated, resp)
	h.audit.HTTP(r, audit.EventSetupComplete, audit.OutcomeSuccess, "", resp.UserID, nil)
}

// setupRequired reports whether the server is waiting for its first admin. A
// failed check counts as not required, so an unreachable database never
// invents a setup screen.
func (h *Handler) setupRequired(ctx context.Context) bool {
	if h.usecase == nil {
		return false
	}
	required, err := h.usecase.SetupRequired(ctx)
	if err != nil {
		slog.Error("setup required check", "error", err)
		return false
	}
	return required
}
