package server

import (
	"context"
	"encoding/json"
	"log"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/vulnserve/vulnserve/internal/auth"
	"github.com/vulnserve/vulnserve/internal/usecase"
)

func AuthMiddleware(jwtAuth *auth.JWTAuthenticator, apiKeyAuth *auth.APIKeyAuthenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/api/v1/health" {
				next.ServeHTTP(w, r)
				return
			}

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
}

type ingestResponse struct {
	ReportID      string `json:"report_id"`
	TotalFindings int    `json:"total_findings"`
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

	result, err := h.uc.IngestReport(r.Context(), usecase.IngestReportInput{
		ProjectSlug:    req.Project,
		Scanner:        req.Scanner,
		ScannerVersion: req.ScannerVersion,
		ParserVersion:  req.ParserVersion,
		RawData:        req.RawData,
		Branch:         req.Branch,
		CommitSha:      req.CommitSha,
	})
	if err != nil {
		log.Printf("ingest report: %v", err)
		respondError(w, http.StatusUnprocessableEntity, "ingest_failed", err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, ingestResponse{
		ReportID:      result.ReportID,
		TotalFindings: result.TotalFindings,
	})
}
