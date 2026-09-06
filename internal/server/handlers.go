package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/xMinhx/specht/internal/audit"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/usecase"
)

// AuthMiddleware authenticates requests, trying each authenticator in order and storing the identity on the context.
func AuthMiddleware(authenticators ...auth.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if !strings.HasPrefix(header, "Bearer ") {
				respondError(w, http.StatusUnauthorized, "missing_token", "authorization header required")
				return
			}
			token := strings.TrimPrefix(header, "Bearer ")

			for _, a := range authenticators {
				ident, err := a.Authenticate(r.Context(), token)
				if err == nil {
					ctx := auth.ContextWithIdentity(r.Context(), ident)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}

				if errors.Is(err, auth.ErrNotApplicable) {
					continue
				}

				respondError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired token")
				return
			}

			respondError(w, http.StatusUnauthorized, "invalid_token", "invalid or expired token")
		})
	}
}

// LoggerMiddleware logs each request method, path, status, and duration.
func LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Info(
			"request",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
		)
		next.ServeHTTP(w, r)
	})
}

type (
	AuthUsecases interface {
		Register(ctx context.Context, email, password string) (*usecase.AuthResponse, error)
		Login(ctx context.Context, email, password string) (*usecase.AuthResponse, error)
		Refresh(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error)
		Logout(ctx context.Context, refreshToken string) error
		GetProfile(ctx context.Context, userID string) (*usecase.UserProfile, error)
	}

	APIKeyUsecases interface {
		CreateAPIKey(ctx context.Context, projectSlug, name, createdBy string) (*usecase.APIKeyResponse, error)
		ListAPIKeys(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error)
		RevokeAPIKey(ctx context.Context, projectSlug, keyID string) error
	}

	ProjectUsecases interface {
		CreateProject(ctx context.Context, name, slug, description string) (*usecase.ProjectResponse, error)
		ListProjects(ctx context.Context) ([]usecase.ProjectResponse, error)
		GetProject(ctx context.Context, slug string) (*usecase.ProjectResponse, error)
		ListEnvironments(ctx context.Context, projectSlug string) ([]usecase.EnvironmentResponse, error)
		ListTargets(ctx context.Context, projectSlug string) ([]usecase.TargetResponse, error)
		ListArtifacts(ctx context.Context, projectSlug string) ([]usecase.ArtifactResponse, error)
	}

	FindingUsecases interface {
		ListFindings(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, error)
		GetFinding(ctx context.Context, findingID string) (*usecase.FindingResponse, error)
		TriageFinding(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error)
		VerifyFix(ctx context.Context, findingID string) (*usecase.VerifyResponse, error)
		BulkTriage(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error)
		GetFindingEvents(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]usecase.FindingEvent, error)
	}

	ReportUsecases interface {
		IngestReport(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error)
		ListReports(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error)
		GetReport(ctx context.Context, reportID string) (*usecase.ReportResponse, error)
	}

	GateUsecases interface {
		GetGateStatus(ctx context.Context, projectSlug string, minSeverityRank int16) (*usecase.GateStatusOutput, error)
	}

	WaiverUsecases interface {
		CreateWaiver(ctx context.Context, input usecase.CreateWaiverInput) (*usecase.WaiverResponse, error)
		ListWaivers(ctx context.Context, projectSlug string) ([]usecase.WaiverResponse, error)
		GetWaiver(ctx context.Context, projectSlug, waiverID string) (*usecase.WaiverDetailResponse, error)
		UpdateWaiver(ctx context.Context, input usecase.UpdateWaiverInput) (*usecase.WaiverResponse, error)
		DeleteWaiver(ctx context.Context, projectSlug, waiverID string) error
		ToggleWaiver(ctx context.Context, projectSlug, waiverID, actorID string) (*usecase.WaiverResponse, error)
		ListWaiverEvents(ctx context.Context, projectSlug, waiverID string) ([]usecase.WaiverEventResp, error)
		CheckWaiverMatch(ctx context.Context, projectSlug, findingID string) (bool, error)
	}

	EvidenceUsecases interface {
		CreateEvidence(ctx context.Context, findingID, userID, typ, url, description string) (usecase.EvidenceResponse, error)
		ListEvidence(ctx context.Context, findingID string) ([]usecase.EvidenceResponse, error)
		DeleteEvidence(ctx context.Context, evidenceID string) error
	}

	ReachabilityUsecases interface {
		UpsertReachability(ctx context.Context, findingID, userID, state, evidence string) (*usecase.ReachabilityResponse, error)
		ListReachability(ctx context.Context, findingID string) ([]usecase.ReachabilityResponse, error)
	}

	SignoffUsecases interface {
		UpsertSignoff(ctx context.Context, findingID, userID, status, comment string) (*usecase.SignoffResponse, error)
		GetSignoff(ctx context.Context, findingID string) (*usecase.SignoffResponse, error)
	}

	StatsUsecases interface {
		GetProjectStats(ctx context.Context, projectSlug string) (*usecase.ProjectStats, error)
		GetAging(ctx context.Context, projectSlug string) (*usecase.AgingResponse, error)
	}

	WatcherUsecases interface {
		GetWatcherStatus(ctx context.Context) (*usecase.WatcherStatusResponse, error)
	}

	// ScannerUsecases exposes deterministic scanner capability discovery.
	ScannerUsecases interface {
		ListScanners() []usecase.ScannerDescriptorResponse
	}
)

// Handler holds the use-case dependency for the HTTP handlers.
type Handler struct {
	usecase usecaseInterface
	audit   *audit.Logger
}

type usecaseInterface interface {
	AuthUsecases
	APIKeyUsecases
	ProjectUsecases
	FindingUsecases
	ReportUsecases
	GateUsecases
	WaiverUsecases
	EvidenceUsecases
	ReachabilityUsecases
	SignoffUsecases
	StatsUsecases
	WatcherUsecases
	ScannerUsecases
}

// NewHandler builds the HTTP handlers over a use-case implementation.
func NewHandler(uc usecaseInterface) *Handler {
	return &Handler{usecase: uc, audit: audit.NewLogger(nil)}
}

type ingestRequest struct {
	Project         string          `json:"project"`
	Scanner         string          `json:"scanner"`
	ScannerVersion  string          `json:"scanner_version,omitempty"`
	ParserVersion   string          `json:"parser_version,omitempty"`
	RawData         json.RawMessage `json:"raw_data"`
	Branch          string          `json:"branch,omitempty"`
	CommitSha       string          `json:"commit_sha,omitempty"`
	GateSeverity    string          `json:"gate_severity,omitempty"`
	GateStatus      string          `json:"gate_status,omitempty"`
	Environment     string          `json:"environment,omitempty"`
	Owner           string          `json:"owner,omitempty"`
	Digest          string          `json:"digest,omitempty"`
	ArtifactName    string          `json:"artifact_name,omitempty"`
	ArtifactVersion string          `json:"artifact_version,omitempty"`
	ArtifactType    string          `json:"artifact_type,omitempty"`
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

// maxPageSize bounds a single paginated request; larger limits are clamped.
const maxPageSize = 500

func parseIntParam(r *http.Request, name string, defaultVal int32) int32 {
	val := r.URL.Query().Get(name)
	if val == "" {
		return defaultVal
	}
	// Parse with 32-bit size so oversized values error out instead of silently
	// truncating to a negative int32 (PostgreSQL LIMIT -1 means "no limit").
	n, err := strconv.ParseInt(val, 10, 32)
	if err != nil || n < 0 {
		return defaultVal
	}
	if n > maxPageSize {
		return maxPageSize
	}
	return int32(n)
}

func (h *Handler) enforceProjectAccess(r *http.Request, projectSlug string) error {
	ident := auth.ContextIdentity(r.Context())
	if ident == nil {
		return fmt.Errorf("project_access_denied")
	}
	if ident.ProjectID == "" || !ident.IsAPIKey {
		return nil // session users are global
	}
	if h.usecase == nil {
		return fmt.Errorf("project_access_denied")
	}
	project, err := h.usecase.GetProject(r.Context(), projectSlug)
	if err != nil || project == nil || project.ID != ident.ProjectID {
		return fmt.Errorf("project_access_denied")
	}
	return nil
}

// RequireRole is a middleware that enforces a minimum role for session-authenticated
// users. API keys bypass role checks (they are already project-scoped). Unauthenticated
// requests fall through to 401.
//
// The identity's role is validated against the canonical RBAC vocabulary
// (auth.ValidRole) before the demanded-role check: a token carrying a role
// outside admin/editor/viewer — the legacy DB role "member", an empty claim,
// or garbage — is not a known principal and is denied 403, never admitted
// just because no demanded role matched it.
func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ident := auth.ContextIdentity(r.Context())
			if ident == nil {
				respondError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}
			if ident.IsAPIKey {
				next.ServeHTTP(w, r)
				return
			}
			if !auth.ValidRole(ident.Role) || !allowed[ident.Role] {
				respondError(w, http.StatusForbidden, "insufficient_role", "requires admin role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
		return
	}
	limit := parseIntParam(r, "limit", 20)
	offset := parseIntParam(r, "offset", 0)

	var filter usecase.FindingFilter
	if s := r.URL.Query().Get("severity"); s != "" {
		filter.Severities = strings.Split(s, ",")
	}
	if s := r.URL.Query().Get("status"); s != "" {
		filter.States = strings.Split(s, ",")
	}
	if s := r.URL.Query().Get("kind"); s != "" {
		filter.Kinds = strings.Split(s, ",")
	}
	if s := r.URL.Query().Get("environment"); s != "" {
		filter.Environments = strings.Split(s, ",")
	}
	if s := r.URL.Query().Get("target"); s != "" {
		filter.Targets = strings.Split(s, ",")
	}

	findings, err := h.usecase.ListFindings(r.Context(), slug, filter, limit, offset)
	if err != nil {
		log.Printf("list findings: %v", err)
		respondError(w, http.StatusNotFound, "not_found", "project not found")
		return
	}
	respondJSON(w, http.StatusOK, findings)
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
