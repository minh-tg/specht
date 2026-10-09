package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/usecase"
)

const (
	triageMsgInvalidBody          = "invalid request body"
	triageMsgFindingIDRequired    = "finding id is required"
	triageMsgFindingNotFound      = "finding not found"
	triageMsgSlugRequired         = "project slug is required"
	triageMsgProjectAdminRequired = "project admin is required"
	triageMsgPolicyTemplateAbsent = "policy template not found"
	triageMsgTeamIDRequired       = "team id is required"
	triageMsgInvalidTeamID        = "invalid team id format"
	triageMsgTeamNotFound         = "team not found"
	triageMsgTeamAdminRequired    = "team admin is required"
)

// Limit messages derive from the limits themselves so they cannot drift.
var (
	tooManyIDsMessage    = fmt.Sprintf("finding_ids exceeds the maximum of %d", usecase.MaxBulkTriageFindings)
	reasonTooLongMessage = fmt.Sprintf("reason exceeds the maximum of %d bytes", usecase.MaxTriageReasonBytes)
)

func (h *Handler) TriageFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", triageMsgFindingIDRequired)
		return
	}

	var req struct {
		AnalysisState     string     `json:"analysis_state"`
		Reason            string     `json:"reason"`
		AnalysisExpiresAt *time.Time `json:"analysis_expires_at,omitempty"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", triageMsgInvalidBody) {
		return
	}
	if req.AnalysisState == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "analysis_state is required")
		return
	}

	ident := auth.ContextIdentity(r.Context())
	if ident == nil || ident.UserID == "" {
		respondError(w, http.StatusUnauthorized, "unauthorized", "user id required")
		return
	}
	userID := ident.UserID

	result, err := h.usecase.TriageFinding(r.Context(), usecase.TriageInput{
		FindingID:         id,
		AnalysisState:     req.AnalysisState,
		Reason:            req.Reason,
		AnalysisExpiresAt: req.AnalysisExpiresAt,
		UserID:            userID,
	})
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", triageMsgFindingNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondAccessDenied(w, r, "finding")
		case errors.Is(err, usecase.ErrInvalidFindingID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		case errors.Is(err, usecase.ErrReasonRequired):
			respondError(w, http.StatusUnprocessableEntity, "reason_required", "reason is required for this analysis state")
		case errors.Is(err, usecase.ErrReasonTooLong):
			respondError(w, http.StatusBadRequest, "reason_too_long", reasonTooLongMessage)
		case errors.Is(err, usecase.ErrExpiryRequired):
			respondError(w, http.StatusUnprocessableEntity, "expiry_required", "expiry is required for accepted_risk and wont_fix")
		case errors.Is(err, usecase.ErrInvalidState):
			respondError(w, http.StatusUnprocessableEntity, "invalid_state", "invalid analysis state")
		default:
			slog.Error("triage finding", "finding_id", id, "error", err)
			respondError(w, http.StatusInternalServerError, "triage_failed", "could not update finding analysis state")
		}
		return
	}
	respondJSON(w, http.StatusOK, result)
	h.audit.HTTP(r, audit.EventTriageFinding, audit.OutcomeSuccess, "", id, nil)
}

func (h *Handler) VerifyFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", triageMsgFindingIDRequired)
		return
	}
	result, err := h.usecase.VerifyFix(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", triageMsgFindingNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondAccessDenied(w, r, "finding")
		case errors.Is(err, usecase.ErrInvalidFindingID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		default:
			slog.Error("verify finding fix", "finding_id", id, "error", err)
			respondError(w, http.StatusInternalServerError, "verify_failed", "could not verify finding fix")
		}
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) BulkTriage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FindingIDs        []string   `json:"finding_ids"`
		AnalysisState     string     `json:"analysis_state"`
		Reason            string     `json:"reason"`
		AnalysisExpiresAt *time.Time `json:"analysis_expires_at,omitempty"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", triageMsgInvalidBody) {
		return
	}
	if len(req.FindingIDs) == 0 {
		respondError(w, http.StatusBadRequest, "missing_field", "finding_ids is required")
		return
	}
	if len(req.FindingIDs) > maxBulkFindingIDs {
		respondError(w, http.StatusBadRequest, "too_many_ids", tooManyIDsMessage)
		return
	}
	if req.AnalysisState == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "analysis_state is required")
		return
	}

	ident := auth.ContextIdentity(r.Context())
	if ident == nil || ident.UserID == "" {
		respondError(w, http.StatusUnauthorized, "unauthorized", "user id required")
		return
	}
	userID := ident.UserID

	results, err := h.usecase.BulkTriage(r.Context(), usecase.BulkTriageInput{
		FindingIDs:        req.FindingIDs,
		AnalysisState:     req.AnalysisState,
		Reason:            req.Reason,
		AnalysisExpiresAt: req.AnalysisExpiresAt,
		UserID:            userID,
	})
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", "one or more findings not found")
		case errors.Is(err, usecase.ErrInvalidFindingID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondAccessDenied(w, r, "finding")
		case errors.Is(err, usecase.ErrReasonRequired):
			respondError(w, http.StatusUnprocessableEntity, "reason_required", "reason is required for this analysis state")
		case errors.Is(err, usecase.ErrReasonTooLong):
			respondError(w, http.StatusBadRequest, "reason_too_long", reasonTooLongMessage)
		case errors.Is(err, usecase.ErrTooManyFindings):
			respondError(w, http.StatusBadRequest, "too_many_ids", tooManyIDsMessage)
		case errors.Is(err, usecase.ErrExpiryRequired):
			respondError(w, http.StatusUnprocessableEntity, "expiry_required", "expiry is required for accepted_risk and wont_fix")
		case errors.Is(err, usecase.ErrInvalidState):
			respondError(w, http.StatusUnprocessableEntity, "invalid_state", "invalid analysis state")
		default:
			slog.Error("bulk triage", "error", err)
			respondError(w, http.StatusInternalServerError, "bulk_triage_failed", "could not update finding analysis states")
		}
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (h *Handler) GetGateStatus(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", triageMsgSlugRequired)
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}

	minRank := parseMinSeverityRank(r.URL.Query().Get("severity"))
	if r.URL.Query().Get("severity") == "" {
		// No explicit severity: the project's effective policy decides
		// the floor (0 is the "use policy" sentinel in GetGateStatus).
		minRank = 0
	}

	if r.URL.Query().Get("introduced_only") == "1" || r.URL.Query().Get("introduced_only") == "true" {
		reportID := r.URL.Query().Get("report_id")
		if reportID == "" {
			respondError(w, http.StatusBadRequest, "missing_report_id", "report_id is required with introduced_only")
			return
		}
		result, err := h.usecase.GetIntroducedGateStatus(r.Context(), slug, minRank, reportID)
		if err != nil {
			slog.Error("get introduced gate status", "project", slug, "error", err)
			respondError(w, http.StatusInternalServerError, "gate_failed", "could not evaluate gate status")
			return
		}
		respondJSON(w, http.StatusOK, result)
		return
	}

	result, err := h.usecase.GetGateStatus(r.Context(), slug, minRank)
	if err != nil {
		slog.Error("get gate status", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "gate_failed", "could not evaluate gate status")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) PreviewPRCheck(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", triageMsgSlugRequired)
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	q := r.URL.Query()
	commit := q.Get("commit")
	if commit == "" {
		respondError(w, http.StatusBadRequest, "missing_commit", "commit is required")
		return
	}

	result, err := h.usecase.PreviewPRCheck(r.Context(), usecase.PRCheckPreviewInput{
		ProjectSlug:     slug,
		Provider:        q.Get("provider"),
		CommitSha:       commit,
		ReportID:        q.Get("report_id"),
		MinSeverityRank: parseMinSeverityRank(q.Get("severity")),
	})
	if err != nil {
		if errors.Is(err, usecase.ErrUnknownProvider) {
			respondError(w, http.StatusBadRequest, "unknown_provider", "unknown provider")
			return
		}
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondAccessDenied(w, r, "report")
			return
		}
		slog.Error("preview pr check", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "pr_check_failed", "could not plan pull-request check")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) PreviewPatch(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", triageMsgFindingIDRequired)
		return
	}

	result, err := h.usecase.PreviewPatch(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidFindingID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", triageMsgFindingNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondAccessDenied(w, r, "finding")
		default:
			slog.Error("preview patch", "finding_id", id, "error", err)
			respondError(w, http.StatusInternalServerError, "patch_failed", "could not plan patch")
		}
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) PreviewNotification(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", triageMsgFindingIDRequired)
		return
	}
	q := r.URL.Query()
	channel := q.Get("channel")
	if channel == "" {
		respondError(w, http.StatusBadRequest, "missing_channel", "channel is required (issue or message)")
		return
	}
	target := q.Get("target")
	if target == "" {
		respondError(w, http.StatusBadRequest, "missing_target", "target is required (integration and scope)")
		return
	}
	linked := q.Get("linked") == "1" || q.Get("linked") == "true"

	result, err := h.usecase.PreviewNotification(r.Context(), id, channel, target, linked)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidFindingID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid finding id format")
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", triageMsgFindingNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondAccessDenied(w, r, "finding")
		default:
			slog.Error("preview notification", "finding_id", id, "error", err)
			respondError(w, http.StatusInternalServerError, "notify_failed", "could not plan notification")
		}
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) GetAdminStatus(w http.ResponseWriter, r *http.Request) {
	result, err := h.usecase.GetAdminStatus(r.Context())
	if err != nil {
		slog.Error("get admin status", "error", err)
		respondError(w, http.StatusInternalServerError, "admin_failed", "could not load platform status")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) PreviewRetention(w http.ResponseWriter, r *http.Request) {
	days, ok := parseRetentionDays(w, r)
	if !ok {
		return
	}

	result, err := h.usecase.PreviewRetention(r.Context(), days)
	if err != nil {
		slog.Error("preview retention", "error", err)
		respondError(w, http.StatusInternalServerError, "retention_failed", "could not preview retention")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) PurgeRetention(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OlderThanDays int `json:"older_than_days"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", triageMsgInvalidBody) {
		return
	}
	if req.OlderThanDays <= 0 || req.OlderThanDays > 3650 {
		respondError(w, http.StatusBadRequest, "invalid_window", "older_than_days must be between 1 and 3650")
		return
	}

	result, err := h.usecase.PurgeRetention(r.Context(), req.OlderThanDays)
	if err != nil {
		slog.Error("purge retention", "error", err)
		respondError(w, http.StatusInternalServerError, "retention_failed", "could not purge reports")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

// parseRetentionDays reads the days query parameter for retention preview.
// It reports false after writing the error response when the window is
// missing or out of range.
func parseRetentionDays(w http.ResponseWriter, r *http.Request) (int, bool) {
	raw := r.URL.Query().Get("days")
	days, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || days <= 0 || days > 3650 {
		respondError(w, http.StatusBadRequest, "invalid_window", "days must be between 1 and 3650")
		return 0, false
	}
	return days, true
}

func (h *Handler) ListPolicyTemplates(w http.ResponseWriter, r *http.Request) {
	result, err := h.usecase.ListPolicyTemplates(r.Context())
	if err != nil {
		slog.Error("list policy templates", "error", err)
		respondError(w, http.StatusInternalServerError, "policy_failed", "could not list policy templates")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) CreatePolicyTemplate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Definition  json.RawMessage `json:"definition"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", triageMsgInvalidBody) {
		return
	}

	result, err := h.usecase.CreatePolicyTemplate(r.Context(), req.Name, req.Description, req.Definition)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrPolicyConflict):
			respondError(w, http.StatusConflict, "policy_conflict", "a template with this name exists")
		default:
			slog.Error("create policy template", "error", err)
			respondError(w, http.StatusBadRequest, "invalid_policy", "invalid policy template")
		}
		return
	}

	respondJSON(w, http.StatusCreated, result)
}

func (h *Handler) UpdatePolicyTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "template id is required")
		return
	}
	var req struct {
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Definition  json.RawMessage `json:"definition"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", triageMsgInvalidBody) {
		return
	}

	result, err := h.usecase.UpdatePolicyTemplate(r.Context(), id, req.Name, req.Description, req.Definition)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid template id format")
		case errors.Is(err, usecase.ErrPolicyNotFound):
			respondError(w, http.StatusNotFound, "not_found", triageMsgPolicyTemplateAbsent)
		case errors.Is(err, usecase.ErrPolicyConflict):
			respondError(w, http.StatusConflict, "policy_conflict", "a template with this name exists")
		default:
			slog.Error("update policy template", "error", err)
			respondError(w, http.StatusBadRequest, "invalid_policy", "invalid policy template")
		}
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) DeletePolicyTemplate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "template id is required")
		return
	}

	if err := h.usecase.DeletePolicyTemplate(r.Context(), id); err != nil {
		if errors.Is(err, usecase.ErrInvalidID) {
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid template id format")
			return
		}
		if errors.Is(err, usecase.ErrPolicyNotFound) {
			respondError(w, http.StatusNotFound, "not_found", triageMsgPolicyTemplateAbsent)
			return
		}
		slog.Error("delete policy template", "error", err)
		respondError(w, http.StatusInternalServerError, "policy_failed", "could not delete policy template")
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) SetProjectPolicy(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", triageMsgSlugRequired)
		return
	}
	var req struct {
		TemplateName string `json:"template_name"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", triageMsgInvalidBody) {
		return
	}

	result, err := h.usecase.SetProjectPolicy(r.Context(), slug, req.TemplateName)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", triageMsgProjectAdminRequired)
		case errors.Is(err, usecase.ErrPolicyNotFound):
			respondError(w, http.StatusNotFound, "not_found", triageMsgPolicyTemplateAbsent)
		default:
			slog.Error("set project policy", "project", slug, "error", err)
			respondError(w, http.StatusInternalServerError, "policy_failed", "could not assign policy template")
		}
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) SetProjectPolicyOverrides(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", triageMsgSlugRequired)
		return
	}
	var req struct {
		Overrides map[string]string `json:"overrides"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", triageMsgInvalidBody) {
		return
	}

	result, err := h.usecase.SetProjectPolicyOverrides(r.Context(), slug, req.Overrides)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", triageMsgProjectAdminRequired)
		default:
			slog.Error("set policy overrides", "project", slug, "error", err)
			respondError(w, http.StatusBadRequest, "invalid_policy", "invalid policy overrides")
		}
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) GetEffectivePolicy(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", triageMsgSlugRequired)
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}

	result, err := h.usecase.EffectivePolicy(r.Context(), slug)
	if err != nil {
		slog.Error("get effective policy", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "policy_failed", "could not resolve policy")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) ListTeams(w http.ResponseWriter, r *http.Request) {
	result, err := h.usecase.ListTeams(r.Context())
	if err != nil {
		if errors.Is(err, usecase.ErrProjectAccessDenied) {
			respondError(w, http.StatusForbidden, "project_access_denied", projectsMsgAccessDenied)
			return
		}
		slog.Error("list teams", "error", err)
		respondError(w, http.StatusInternalServerError, "teams_failed", "could not list teams")
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) CreateTeam(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", triageMsgInvalidBody) {
		return
	}

	result, err := h.usecase.CreateTeam(r.Context(), req.Name, req.Description)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrTeamConflict):
			respondError(w, http.StatusConflict, "team_conflict", "a team with this name exists")
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "forbidden", "session authentication is required")
		default:
			slog.Error("create team", "error", err)
			respondError(w, http.StatusBadRequest, "invalid_team", "invalid team")
		}
		return
	}

	respondJSON(w, http.StatusCreated, result)
}

func (h *Handler) DeleteTeam(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", triageMsgTeamIDRequired)
		return
	}

	if err := h.usecase.DeleteTeam(r.Context(), id); err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidID):
			respondError(w, http.StatusBadRequest, "invalid_id", triageMsgInvalidTeamID)
		case errors.Is(err, usecase.ErrTeamNotFound):
			respondError(w, http.StatusNotFound, "not_found", triageMsgTeamNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "forbidden", "global admin is required")
		default:
			slog.Error("delete team", "error", err)
			respondError(w, http.StatusInternalServerError, "teams_failed", "could not delete team")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListTeamMembers(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", triageMsgTeamIDRequired)
		return
	}

	result, err := h.usecase.ListTeamMembers(r.Context(), id)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidID):
			respondError(w, http.StatusBadRequest, "invalid_id", triageMsgInvalidTeamID)
		case errors.Is(err, usecase.ErrTeamNotFound):
			respondError(w, http.StatusNotFound, "not_found", triageMsgTeamNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "forbidden", triageMsgTeamAdminRequired)
		default:
			slog.Error("list team members", "error", err)
			respondError(w, http.StatusInternalServerError, "teams_failed", "could not list team members")
		}
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) AddTeamMember(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", triageMsgTeamIDRequired)
		return
	}
	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", triageMsgInvalidBody) {
		return
	}

	result, err := h.usecase.AddTeamMember(r.Context(), id, req.UserID, req.Role)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrTeamNotFound):
			respondError(w, http.StatusNotFound, "not_found", triageMsgTeamNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "forbidden", triageMsgTeamAdminRequired)
		case errors.Is(err, usecase.ErrInvalidID),
			errors.Is(err, usecase.ErrInvalidMemberRole),
			errors.Is(err, usecase.ErrMemberUserNotFound):
			respondMemberError(w, err)
		default:
			slog.Error("add team member", "error", err)
			respondError(w, http.StatusInternalServerError, "internal_error", "could not add team member")
		}
		return
	}

	respondJSON(w, http.StatusCreated, result)
}

func (h *Handler) RemoveTeamMember(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	userID := chi.URLParam(r, "userID")
	if id == "" || userID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "team id and user id are required")
		return
	}

	if err := h.usecase.RemoveTeamMember(r.Context(), id, userID); err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidID):
			respondError(w, http.StatusBadRequest, "invalid_id", "invalid id format")
		case errors.Is(err, usecase.ErrTeamNotFound):
			respondError(w, http.StatusNotFound, "not_found", triageMsgTeamNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "forbidden", triageMsgTeamAdminRequired)
		default:
			slog.Error("remove team member", "error", err)
			respondError(w, http.StatusInternalServerError, "teams_failed", "could not remove team member")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListProjectTeams(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", triageMsgSlugRequired)
		return
	}

	result, err := h.usecase.ListProjectTeams(r.Context(), slug)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", triageMsgProjectAdminRequired)
		default:
			slog.Error("list project teams", "project", slug, "error", err)
			respondError(w, http.StatusInternalServerError, "teams_failed", "could not list project teams")
		}
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) LinkProjectTeam(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", triageMsgSlugRequired)
		return
	}
	var req struct {
		TeamID string `json:"team_id"`
		Role   string `json:"role"`
	}
	if !decodeJSONBody(w, r, &req, maxJSONBodyBytes, "invalid_json", triageMsgInvalidBody) {
		return
	}

	result, err := h.usecase.LinkProjectTeam(r.Context(), slug, req.TeamID, req.Role)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", triageMsgProjectAdminRequired)
		case errors.Is(err, usecase.ErrTeamNotFound):
			respondError(w, http.StatusNotFound, "not_found", triageMsgTeamNotFound)
		default:
			slog.Error("link project team", "project", slug, "error", err)
			respondError(w, http.StatusBadRequest, "invalid_link", "invalid project team link")
		}
		return
	}

	respondJSON(w, http.StatusCreated, result)
}

func (h *Handler) UnlinkProjectTeam(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	teamID := chi.URLParam(r, "teamID")
	if slug == "" || teamID == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "project slug and team id are required")
		return
	}

	if err := h.usecase.UnlinkProjectTeam(r.Context(), slug, teamID); err != nil {
		switch {
		case errors.Is(err, usecase.ErrInvalidID):
			respondError(w, http.StatusBadRequest, "invalid_id", triageMsgInvalidTeamID)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondError(w, http.StatusForbidden, "project_access_denied", triageMsgProjectAdminRequired)
		default:
			slog.Error("unlink project team", "project", slug, "error", err)
			respondError(w, http.StatusInternalServerError, "teams_failed", "could not unlink project team")
		}
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) ListFindingEvents(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", triageMsgFindingIDRequired)
		return
	}

	limit := parseIntParam(r, "limit", 50)
	offset := parseOffsetParam(r, "offset", 0)

	events, err := h.usecase.GetFindingEvents(r.Context(), id, nil, limit, offset)
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", triageMsgFindingNotFound)
		case errors.Is(err, usecase.ErrProjectAccessDenied):
			respondAccessDenied(w, r, "finding")
		default:
			slog.Error("list finding events", "finding_id", id, "error", err)
			respondError(w, http.StatusInternalServerError, "events_failed", "could not list finding events")
		}
		return
	}

	respondJSON(w, http.StatusOK, events)
}

func (h *Handler) ListEnvironments(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", triageMsgSlugRequired)
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	envs, err := h.usecase.ListEnvironments(r.Context(), slug)
	if err != nil {
		slog.Error("list environments", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "environments_failed", "could not list environments")
		return
	}
	respondJSON(w, http.StatusOK, envs)
}

func (h *Handler) ListTargets(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", triageMsgSlugRequired)
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	targets, err := h.usecase.ListTargets(r.Context(), slug)
	if err != nil {
		slog.Error("list targets", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "targets_failed", "could not list targets")
		return
	}
	respondJSON(w, http.StatusOK, targets)
}

func (h *Handler) ListArtifacts(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", triageMsgSlugRequired)
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	artifacts, err := h.usecase.ListArtifacts(r.Context(), slug)
	if err != nil {
		slog.Error("list artifacts", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "artifacts_failed", "could not list artifacts")
		return
	}
	respondJSON(w, http.StatusOK, artifacts)
}

func (h *Handler) GetProjectStats(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", triageMsgSlugRequired)
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	stats, err := h.usecase.GetProjectStats(r.Context(), slug)
	if err != nil {
		slog.Error("get project stats", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "stats_failed", "could not compute project statistics")
		return
	}
	respondJSON(w, http.StatusOK, stats)
}

func (h *Handler) GetAging(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", triageMsgSlugRequired)
		return
	}
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, r, err)
		return
	}
	resp, err := h.usecase.GetAging(r.Context(), slug)
	if err != nil {
		slog.Error("get aging", "project", slug, "error", err)
		respondError(w, http.StatusInternalServerError, "aging_failed", "could not compute aging report")
		return
	}
	respondJSON(w, http.StatusOK, resp)
}
