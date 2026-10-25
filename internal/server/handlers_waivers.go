package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/usecase"
)

const (
	waiversMsgInvalidBody = "invalid request body"
	waiversMsgNotFound    = "waiver not found"
)

func (h *Handler) CreateWaiver(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		ExpiresAt   string `json:"expires_at,omitempty"`
		// Scope is "all" for a waiver that covers every finding. Otherwise it
		// stays empty and the conditions, contexts or target_ids define the scope.
		Scope      string                               `json:"scope,omitempty"`
		Conditions []usecase.CreateWaiverConditionInput `json:"conditions,omitempty"`
		Contexts   []usecase.CreateWaiverContextInput   `json:"contexts,omitempty"`
		TargetIDs  []string                             `json:"target_ids,omitempty"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_body", waiversMsgInvalidBody) {
		return
	}
	if req.Name == "" {
		respondError(w, http.StatusBadRequest, "invalid_body", "name is required")
		return
	}
	scopeAll, ok := parseWaiverScope(w, req.Scope)
	if !ok {
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

	var actorID string
	if ident := auth.ContextIdentity(r.Context()); ident != nil {
		actorID = ident.UserID
	}

	result, err := h.usecase.CreateWaiver(r.Context(), usecase.CreateWaiverInput{
		ProjectSlug: slug,
		Name:        req.Name,
		Description: req.Description,
		ExpiresAt:   expiresAt,
		ScopeAll:    scopeAll,
		Conditions:  req.Conditions,
		Contexts:    req.Contexts,
		TargetIDs:   req.TargetIDs,
		ActorID:     actorID,
	})
	if err != nil {
		if h.respondWaiverError(w, r, err) {
			return
		}
		slog.Error("create waiver", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not create waiver")
		return
	}
	respondJSON(w, http.StatusCreated, result)
}

func (h *Handler) ListWaivers(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	var statuses []string
	if s := r.URL.Query().Get("status"); s != "" {
		statuses = strings.Split(s, ",")
		for _, status := range statuses {
			if !validWaiverStatus(status) {
				respondError(w, http.StatusBadRequest, "invalid_status",
					"status must be a comma list of pending, approved, rejected, withdrawn")
				return
			}
		}
	}
	waivers, err := h.usecase.ListWaivers(r.Context(), slug, statuses...)
	if err != nil {
		slog.Error("list waivers", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not list waivers")
		return
	}
	respondJSON(w, http.StatusOK, waivers)
}

func (h *Handler) GetWaiver(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	id := chi.URLParam(r, "id")
	waiver, err := h.usecase.GetWaiver(r.Context(), slug, id)
	if err != nil {
		if h.respondWaiverError(w, r, err) {
			return
		}
		slog.Error("get waiver", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not get waiver")
		return
	}
	respondJSON(w, http.StatusOK, waiver)
}

func (h *Handler) UpdateWaiver(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		// ExpiresAt is the update tri-state: omitted keeps the stored
		// expiry, "" clears it, an RFC3339 value sets it.
		ExpiresAt  *string                              `json:"expires_at"`
		Scope      string                               `json:"scope,omitempty"`
		Conditions []usecase.CreateWaiverConditionInput `json:"conditions,omitempty"`
		Contexts   []usecase.CreateWaiverContextInput   `json:"contexts,omitempty"`
		TargetIDs  []string                             `json:"target_ids,omitempty"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_body", waiversMsgInvalidBody) {
		return
	}

	scopeAll, ok := parseWaiverScope(w, req.Scope)
	if !ok {
		return
	}

	var expiresAt *time.Time
	clearExpires := false
	if req.ExpiresAt != nil {
		if *req.ExpiresAt == "" {
			clearExpires = true
		} else {
			parsed, err := time.Parse(time.RFC3339, *req.ExpiresAt)
			if err != nil {
				respondError(w, http.StatusBadRequest, "invalid_expires_at", "expires_at must be an RFC3339 timestamp")
				return
			}
			expiresAt = &parsed
		}
	}

	var actorID string
	if ident := auth.ContextIdentity(r.Context()); ident != nil {
		actorID = ident.UserID
	}

	result, err := h.usecase.UpdateWaiver(r.Context(), usecase.UpdateWaiverInput{
		WaiverID:       id,
		ProjectSlug:    slug,
		Name:           req.Name,
		Description:    req.Description,
		ExpiresAt:      expiresAt,
		ClearExpiresAt: clearExpires,
		ScopeAll:       scopeAll,
		Conditions:     req.Conditions,
		Contexts:       req.Contexts,
		TargetIDs:      req.TargetIDs,
		ActorID:        actorID,
	})
	if err != nil {
		if h.respondWaiverError(w, r, err) {
			return
		}
		slog.Error("update waiver", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not update waiver")
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) DeleteWaiver(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	id := chi.URLParam(r, "id")
	if err := h.usecase.DeleteWaiver(r.Context(), slug, id); err != nil {
		if h.respondWaiverError(w, r, err) {
			return
		}
		slog.Error("delete waiver", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not delete waiver")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ToggleWaiver flips an approved waiver. It is deprecated: the flip is blind,
// so two callers can undo each other. RevokeWaiver and RestoreWaiver name the
// wanted state instead.
func (h *Handler) ToggleWaiver(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	id := chi.URLParam(r, "id")
	var actorID string
	if ident := auth.ContextIdentity(r.Context()); ident != nil {
		actorID = ident.UserID
	}
	result, err := h.usecase.ToggleWaiver(r.Context(), slug, id, actorID)
	if err != nil {
		if h.respondWaiverError(w, r, err) {
			return
		}
		slog.Error("toggle waiver", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not toggle waiver")
		return
	}
	respondJSON(w, http.StatusOK, result)
	h.audit.HTTP(r, audit.EventToggleWaiver, audit.OutcomeSuccess, slug, id, nil)
}

// RevokeWaiver switches an approved waiver off. The body is optional; an
// expected_updated_at in it makes the call fail with 409 waiver_changed when
// the waiver was written after that version.
func (h *Handler) RevokeWaiver(w http.ResponseWriter, r *http.Request) {
	h.setWaiverEnabled(w, r, audit.EventRevokeWaiver, "revoke waiver", h.usecase.RevokeWaiver)
}

// RestoreWaiver switches a revoked waiver back on, unless it has expired.
func (h *Handler) RestoreWaiver(w http.ResponseWriter, r *http.Request) {
	h.setWaiverEnabled(w, r, audit.EventRestoreWaiver, "restore waiver", h.usecase.RestoreWaiver)
}

func (h *Handler) setWaiverEnabled(
	w http.ResponseWriter, r *http.Request, event, action string,
	apply func(ctx context.Context, projectSlug, waiverID, actorID string, expectedUpdatedAt *time.Time) (*usecase.WaiverResponse, error),
) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		ExpectedUpdatedAt string `json:"expected_updated_at"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_body", waiversMsgInvalidBody) {
		return
	}
	var expected *time.Time
	if req.ExpectedUpdatedAt != "" {
		parsed, err := time.Parse(time.RFC3339Nano, req.ExpectedUpdatedAt)
		if err != nil {
			respondError(w, http.StatusBadRequest, "invalid_expected_updated_at", "expected_updated_at must be an RFC3339 timestamp")
			return
		}
		expected = &parsed
	}
	var actorID string
	if ident := auth.ContextIdentity(r.Context()); ident != nil {
		actorID = ident.UserID
	}
	result, err := apply(r.Context(), slug, id, actorID, expected)
	if err != nil {
		if h.respondWaiverError(w, r, err) {
			return
		}
		slog.Error(action, "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not "+action)
		return
	}
	respondJSON(w, http.StatusOK, result)
	h.audit.HTTP(r, event, audit.OutcomeSuccess, slug, id, nil)
}

func (h *Handler) ListWaiverEvents(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	id := chi.URLParam(r, "id")
	events, err := h.usecase.ListWaiverEvents(r.Context(), slug, id)
	if err != nil {
		if h.respondWaiverError(w, r, err) {
			return
		}
		slog.Error("list waiver events", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not list waiver events")
		return
	}
	respondJSON(w, http.StatusOK, events)
}

func (h *Handler) CheckWaiverMatch(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	var req struct {
		FindingID string `json:"finding_id"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_body", waiversMsgInvalidBody) {
		return
	}
	if req.FindingID == "" {
		respondError(w, http.StatusBadRequest, "invalid_body", "finding_id is required")
		return
	}
	matched, err := h.usecase.CheckWaiverMatch(r.Context(), slug, req.FindingID)
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			h.respondProjectAccessError(w, r, errProjectAccessDenied)
			return
		}
		slog.Error("check waiver match", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not check waiver match")
		return
	}
	respondJSON(w, http.StatusOK, map[string]bool{"matched": matched})
}

// validWaiverStatus reports whether s names a waiver review state.
func validWaiverStatus(s string) bool {
	switch s {
	case usecase.WaiverStatusPending, usecase.WaiverStatusApproved,
		usecase.WaiverStatusRejected, usecase.WaiverStatusWithdrawn:
		return true
	}
	return false
}

// parseWaiverScope reads the scope field of a waiver body. It answers false
// after writing a 400 when the value is not "all" or empty.
func parseWaiverScope(w http.ResponseWriter, scope string) (scopeAll, ok bool) {
	switch scope {
	case "":
		return false, true
	case "all":
		return true, true
	}
	respondError(w, http.StatusBadRequest, "invalid_scope", `scope must be "all" or omitted`)
	return false, false
}

// respondWaiverError maps the waiver lifecycle errors to responses. It
// returns false for errors it does not recognise so the caller can report
// them as internal errors.
func (h *Handler) respondWaiverError(w http.ResponseWriter, r *http.Request, err error) bool {
	switch {
	case errors.Is(err, usecase.ErrProjectAccessDenied):
		h.respondProjectAccessError(w, r, errProjectAccessDenied)
	case errors.Is(err, usecase.ErrInvalidID):
		respondError(w, http.StatusBadRequest, "invalid_id", "invalid waiver id format")
	case errors.Is(err, usecase.ErrInvalidWaiverRequest):
		respondError(w, http.StatusBadRequest, "invalid_body", err.Error())
	case errors.Is(err, usecase.ErrWaiverScopeNotFound):
		respondError(w, http.StatusNotFound, "not_found", err.Error())
	case errors.Is(err, usecase.ErrWaiverScopeRequired):
		respondError(w, http.StatusBadRequest, "waiver_scope_required", err.Error())
	case errors.Is(err, usecase.ErrWaiverNotPending):
		respondError(w, http.StatusConflict, "waiver_not_pending", err.Error())
	case errors.Is(err, usecase.ErrWaiverExpired), errors.Is(err, usecase.ErrWaiverLapsed):
		respondError(w, http.StatusConflict, "waiver_expired", err.Error())
	case errors.Is(err, usecase.ErrWaiverChanged):
		respondError(w, http.StatusConflict, "waiver_changed", err.Error())
	case errors.Is(err, usecase.ErrWaiverNotApproved):
		respondError(w, http.StatusConflict, "waiver_not_approved", err.Error())
	case errors.Is(err, usecase.ErrWaiverRequestExists):
		respondError(w, http.StatusConflict, "waiver_request_exists", err.Error())
	case errors.Is(err, usecase.ErrWaiverSelfApproval):
		respondError(w, http.StatusForbidden, "self_approval", err.Error())
	case errors.Is(err, port.ErrNotFound):
		respondError(w, http.StatusNotFound, "not_found", waiversMsgNotFound)
	default:
		return false
	}
	return true
}

// RequestWaiver files a pending waiver request for specific findings.
func (h *Handler) RequestWaiver(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	var req struct {
		TargetIDs []string `json:"target_ids"`
		Reason    string   `json:"reason"`
		ExpiresAt string   `json:"expires_at"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_body", waiversMsgInvalidBody) {
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
	result, err := h.usecase.RequestWaiver(r.Context(), usecase.RequestWaiverInput{
		ProjectSlug: slug,
		TargetIDs:   req.TargetIDs,
		Reason:      req.Reason,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		if h.respondWaiverError(w, r, err) {
			return
		}
		slog.Error("request waiver", "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not request waiver")
		return
	}
	respondJSON(w, http.StatusCreated, result)
	h.audit.HTTP(r, audit.EventRequestWaiver, audit.OutcomeSuccess, slug, result.ID, nil)
}

// ApproveWaiver approves a pending waiver request.
func (h *Handler) ApproveWaiver(w http.ResponseWriter, r *http.Request) {
	h.decideWaiver(w, r, audit.EventApproveWaiver, "approve waiver",
		func(slug, id, note string) (*usecase.WaiverResponse, error) {
			return h.usecase.ApproveWaiver(r.Context(), slug, id, note)
		})
}

// RejectWaiver rejects a pending waiver request. The note is required.
func (h *Handler) RejectWaiver(w http.ResponseWriter, r *http.Request) {
	h.decideWaiver(w, r, audit.EventRejectWaiver, "reject waiver",
		func(slug, id, note string) (*usecase.WaiverResponse, error) {
			return h.usecase.RejectWaiver(r.Context(), slug, id, note)
		})
}

// WithdrawWaiver lets the requester take back a pending request.
func (h *Handler) WithdrawWaiver(w http.ResponseWriter, r *http.Request) {
	h.decideWaiver(w, r, audit.EventWithdrawWaiver, "withdraw waiver",
		func(slug, id, _ string) (*usecase.WaiverResponse, error) {
			return h.usecase.WithdrawWaiver(r.Context(), slug, id)
		})
}

// decideWaiver is the shared body of the approve, reject and withdraw routes.
func (h *Handler) decideWaiver(
	w http.ResponseWriter,
	r *http.Request,
	event, action string,
	decide func(slug, id, note string) (*usecase.WaiverResponse, error),
) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	id := chi.URLParam(r, "id")
	var req struct {
		Note string `json:"note"`
	}
	if r.ContentLength != 0 {
		if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_body", waiversMsgInvalidBody) {
			return
		}
	}
	result, err := decide(slug, id, req.Note)
	if err != nil {
		if h.respondWaiverError(w, r, err) {
			return
		}
		slog.Error(action, "error", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "could not "+action)
		return
	}
	respondJSON(w, http.StatusOK, result)
	h.audit.HTTP(r, event, audit.OutcomeSuccess, slug, id, nil)
}
