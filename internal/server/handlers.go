package server

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/usecase"
)

func AuthMiddleware(jwtAuth *auth.JWTAuthenticator, apiKeyAuth *auth.APIKeyAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				respondError(w, http.StatusUnauthorized, "missing_token", "authorization header required")
				return
			}
			token := strings.TrimPrefix(header, "Bearer ")

			ident, err := jwtAuth.Authenticate(r.Context(), token)
			if err == nil {
				ctx := auth.ContextWithIdentity(r.Context(), ident)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			if apiKeyAuth != nil {
				ident, err = apiKeyAuth.Authenticate(r.Context(), token)
				if err == nil {
					ctx := auth.ContextWithIdentity(r.Context(), ident)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
			}

			respondError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired token")
		})
	}
}

func LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
		)
		next.ServeHTTP(w, r)
	})
}

type usecaseInterface interface {
	CreateProject(ctx context.Context, name, slug, description string) (*usecase.ProjectResponse, error)
	IngestReport(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error)
	ListProjects(ctx context.Context) ([]usecase.ProjectResponse, error)
	GetProject(ctx context.Context, slug string) (*usecase.ProjectResponse, error)
	ListFindings(ctx context.Context, projectSlug string, severities, states []string, limit, offset int32) ([]usecase.FindingResponse, error)
	ListReports(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error)
	GetReport(ctx context.Context, reportID pgtype.UUID) (*usecase.ReportResponse, error)
	Register(ctx context.Context, email, password string) (*usecase.AuthResponse, error)
	Login(ctx context.Context, email, password string) (*usecase.AuthResponse, error)
	CreateAPIKey(ctx context.Context, projectSlug, name string) (*usecase.APIKeyResponse, error)
	ListAPIKeys(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error)
	RevokeAPIKey(ctx context.Context, projectSlug, keyID string) error
	TriageFinding(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error)
	BulkTriage(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error)
	GetGateStatus(ctx context.Context, projectSlug string, minSeverityRank int16) (*usecase.GateStatusOutput, error)
	GetFindingEvents(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]sqlc.FindingEvent, error)
	Refresh(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error)
	Logout(ctx context.Context, refreshToken string) error
	GetProfile(ctx context.Context, userID string) (*usecase.UserProfile, error)
}

type Handler struct {
	uc usecaseInterface
}

func NewHandler(uc usecaseInterface) *Handler {
	return &Handler{uc: uc}
}

type ingestRequest struct {
	Project       string          `json:"project"`
	Scanner       string          `json:"scanner"`
	ScannerVersion string         `json:"scanner_version,omitempty"`
	ParserVersion  string         `json:"parser_version,omitempty"`
	RawData       json.RawMessage `json:"raw_data"`
	Branch        string          `json:"branch,omitempty"`
	CommitSha     string          `json:"commit_sha,omitempty"`
	GateSeverity  string          `json:"gate_severity,omitempty"`
	GateStatus    string          `json:"gate_status,omitempty"`
}

type ingestResponse struct {
	ReportID          string `json:"report_id"`
	TotalFindings     int    `json:"total_findings"`
	ThresholdBreached bool   `json:"threshold_breached"`
}

type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("encode response: %v", err)
	}
}

func respondError(w http.ResponseWriter, status int, code, message string) {
	var e apiError
	e.Error.Code = code
	e.Error.Message = message
	respondJSON(w, status, e)
}

func parseIntParam(r *http.Request, name string, defaultVal int32) int32 {
	val := r.URL.Query().Get(name)
	if val == "" {
		return defaultVal
	}
	n, err := strconv.Atoi(val)
	if err != nil || n < 0 {
		return defaultVal
	}
	return int32(n)
}

func (h *Handler) CreateProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name        string `json:"name"`
		Slug        string `json:"slug"`
		Description string `json:"description,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}
	if req.Name == "" || req.Slug == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "name and slug are required")
		return
	}

	result, err := h.uc.CreateProject(r.Context(), req.Name, req.Slug, req.Description)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "creation_failed", err.Error())
		return
	}
	respondJSON(w, http.StatusCreated, result)
}

func (h *Handler) ListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := h.uc.ListProjects(r.Context())
	if err != nil {
		log.Printf("list projects: %v", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "failed to list projects")
		return
	}
	respondJSON(w, http.StatusOK, projects)
}

func (h *Handler) GetProject(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	project, err := h.uc.GetProject(r.Context(), slug)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	respondJSON(w, http.StatusOK, project)
}

func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	limit := parseIntParam(r, "limit", 20)
	offset := parseIntParam(r, "offset", 0)

	var severities, states []string
	if s := r.URL.Query().Get("severity"); s != "" {
		severities = strings.Split(s, ",")
	}
	if s := r.URL.Query().Get("status"); s != "" {
		states = strings.Split(s, ",")
	}

	findings, err := h.uc.ListFindings(r.Context(), slug, severities, states, limit, offset)
	if err != nil {
		log.Printf("list findings: %v", err)
		respondError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	respondJSON(w, http.StatusOK, findings)
}

func (h *Handler) ListReports(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	limit := parseIntParam(r, "limit", 20)
	offset := parseIntParam(r, "offset", 0)

	reports, err := h.uc.ListReports(r.Context(), slug, limit, offset)
	if err != nil {
		log.Printf("list reports: %v", err)
		respondError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	respondJSON(w, http.StatusOK, reports)
}

func (h *Handler) GetReport(w http.ResponseWriter, r *http.Request) {
	idStr := chi.URLParam(r, "id")
	var id pgtype.UUID
	if err := id.Scan(idStr); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_id", "invalid report id")
		return
	}

	report, err := h.uc.GetReport(r.Context(), id)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", "report not found")
		return
	}
	respondJSON(w, http.StatusOK, report)
}

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}

	result, err := h.uc.Register(r.Context(), req.Email, req.Password)
	if err != nil {
		respondError(w, http.StatusUnprocessableEntity, "registration_failed", err.Error())
		return
	}
	respondJSON(w, http.StatusCreated, result)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}

	result, err := h.uc.Login(r.Context(), req.Email, req.Password)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "login_failed", "invalid email or password")
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) Refresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}

	result, err := h.uc.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "refresh_failed", err.Error())
		return
	}
	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&req)
	}

	if err := h.uc.Logout(r.Context(), req.RefreshToken); err != nil {
		respondError(w, http.StatusInternalServerError, "logout_failed", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	ident := auth.ContextIdentity(r.Context())
	if ident == nil {
		respondError(w, http.StatusUnauthorized, "unauthorized", "not authenticated")
		return
	}

	profile, err := h.uc.GetProfile(r.Context(), ident.UserID)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	respondJSON(w, http.StatusOK, profile)
}

func (h *Handler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Project string `json:"project"`
		Name    string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}
	if req.Project == "" || req.Name == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "project and name are required")
		return
	}

	result, err := h.uc.CreateAPIKey(r.Context(), req.Project, req.Name)
	if err != nil {
		respondError(w, http.StatusUnprocessableEntity, "create_failed", err.Error())
		return
	}
	respondJSON(w, http.StatusCreated, result)
}

func (h *Handler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	if project == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "project query param is required")
		return
	}

	keys, err := h.uc.ListAPIKeys(r.Context(), project)
	if err != nil {
		respondError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	respondJSON(w, http.StatusOK, keys)
}

func (h *Handler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	project := r.URL.Query().Get("project")
	keyID := chi.URLParam(r, "id")
	if project == "" || keyID == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "project and key id are required")
		return
	}

	if err := h.uc.RevokeAPIKey(r.Context(), project, keyID); err != nil {
		respondError(w, http.StatusUnprocessableEntity, "revoke_failed", err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) IngestReport(w http.ResponseWriter, r *http.Request) {
	var req ingestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}

	if req.Project == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "project is required")
		return
	}
	if req.Scanner == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "scanner is required")
		return
	}
	if len(req.RawData) == 0 {
		respondError(w, http.StatusBadRequest, "missing_field", "raw_data is required")
		return
	}

	var gateSeverity, gateStatus []string
	if req.GateSeverity != "" {
		gateSeverity = strings.Split(req.GateSeverity, ",")
	}
	if req.GateStatus != "" {
		gateStatus = strings.Split(req.GateStatus, ",")
	}

	result, err := h.uc.IngestReport(r.Context(), usecase.IngestReportInput{
		ProjectSlug:    req.Project,
		Scanner:        req.Scanner,
		ScannerVersion: req.ScannerVersion,
		ParserVersion:  req.ParserVersion,
		RawData:        req.RawData,
		Branch:         req.Branch,
		CommitSha:      req.CommitSha,
		GateSeverity:   gateSeverity,
		GateStatus:     gateStatus,
	})
	if err != nil {
		log.Printf("ingest report: %v", err)
		if errors.Is(err, usecase.ErrDuplicateReport) {
			respondError(w, http.StatusConflict, "duplicate_report", "report already exists for this project and data")
			return
		}
		respondError(w, http.StatusUnprocessableEntity, "ingest_failed", err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, ingestResponse{
		ReportID:          result.ReportID,
		TotalFindings:     result.TotalFindings,
		ThresholdBreached: result.ThresholdBreached,
	})
}

func (h *Handler) TriageFinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}

	var req struct {
		AnalysisState     string     `json:"analysis_state"`
		Reason            string     `json:"reason"`
		AnalysisExpiresAt *time.Time `json:"analysis_expires_at,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}
	if req.AnalysisState == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "analysis_state is required")
		return
	}

	userID := auth.ContextIdentity(r.Context()).UserID

	result, err := h.uc.TriageFinding(r.Context(), usecase.TriageInput{
		FindingID:         id,
		AnalysisState:     req.AnalysisState,
		Reason:            req.Reason,
		AnalysisExpiresAt: req.AnalysisExpiresAt,
		UserID:            userID,
	})
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", "finding not found")
		case errors.Is(err, usecase.ErrReasonRequired):
			respondError(w, http.StatusUnprocessableEntity, "reason_required", err.Error())
		case errors.Is(err, usecase.ErrExpiryRequired):
			respondError(w, http.StatusUnprocessableEntity, "expiry_required", err.Error())
		default:
			respondError(w, http.StatusInternalServerError, "triage_failed", err.Error())
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
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid_json", "invalid request body")
		return
	}
	if len(req.FindingIDs) == 0 {
		respondError(w, http.StatusBadRequest, "missing_field", "finding_ids is required")
		return
	}
	if req.AnalysisState == "" {
		respondError(w, http.StatusBadRequest, "missing_field", "analysis_state is required")
		return
	}

	userID := auth.ContextIdentity(r.Context()).UserID

	results, err := h.uc.BulkTriage(r.Context(), usecase.BulkTriageInput{
		FindingIDs:        req.FindingIDs,
		AnalysisState:     req.AnalysisState,
		Reason:            req.Reason,
		AnalysisExpiresAt: req.AnalysisExpiresAt,
		UserID:            userID,
	})
	if err != nil {
		switch {
		case errors.Is(err, usecase.ErrFindingNotFound):
			respondError(w, http.StatusNotFound, "not_found", err.Error())
		case errors.Is(err, usecase.ErrReasonRequired):
			respondError(w, http.StatusUnprocessableEntity, "reason_required", err.Error())
		case errors.Is(err, usecase.ErrExpiryRequired):
			respondError(w, http.StatusUnprocessableEntity, "expiry_required", err.Error())
		default:
			respondError(w, http.StatusInternalServerError, "bulk_triage_failed", err.Error())
		}
		return
	}

	respondJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (h *Handler) GetGateStatus(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if slug == "" {
		respondError(w, http.StatusBadRequest, "missing_slug", "project slug is required")
		return
	}

	minRank := parseMinSeverityRank(r.URL.Query().Get("severity"))

	result, err := h.uc.GetGateStatus(r.Context(), slug, minRank)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "gate_failed", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, result)
}

func (h *Handler) ListFindingEvents(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		respondError(w, http.StatusBadRequest, "missing_id", "finding id is required")
		return
	}

	limit := parseIntParam(r, "limit", 50)
	offset := parseIntParam(r, "offset", 0)

	events, err := h.uc.GetFindingEvents(r.Context(), id, nil, limit, offset)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "events_failed", err.Error())
		return
	}

	respondJSON(w, http.StatusOK, events)
}

func parseMinSeverityRank(severities string) int16 {
	if severities == "" {
		return 3 // default: high+
	}
	parts := strings.Split(severities, ",")
	minRank := int16(0)
	for _, p := range parts {
		switch strings.TrimSpace(p) {
		case "critical":
			if 4 > minRank {
				minRank = 4
			}
		case "high":
			if 3 > minRank {
				minRank = 3
			}
		case "medium":
			if 2 > minRank {
				minRank = 2
			}
		case "low":
			if 1 > minRank {
				minRank = 1
			}
		}
	}
	if minRank == 0 {
		return 3
	}
	return minRank
}
