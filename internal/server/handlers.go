package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/xMinhx/specht/internal/audit"
	"github.com/xMinhx/specht/internal/auth"
	"github.com/xMinhx/specht/internal/notify"
	"github.com/xMinhx/specht/internal/patch"
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
		FindOrProvisionSSOUser(ctx context.Context, sub, email string, groups []string, allowedDomains []string, adminGroups []string) (userID, role string, provisioned bool, err error)
		Refresh(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error)
		Logout(ctx context.Context, refreshToken string) error
		GetProfile(ctx context.Context, userID string) (*usecase.UserProfile, error)
		UpdateProfile(ctx context.Context, userID string, displayName *string) (*usecase.UserProfile, error)
	}

	APIKeyUsecases interface {
		CreateAPIKey(ctx context.Context, projectSlug, name, createdBy string, expiresAt *time.Time) (*usecase.APIKeyResponse, error)
		ListAPIKeys(ctx context.Context, projectSlug string) ([]usecase.APIKeyResponse, error)
		RevokeAPIKey(ctx context.Context, projectSlug, keyID string) error
	}

	ProjectUsecases interface {
		CreateProject(ctx context.Context, name, slug, description, creatorID string) (*usecase.ProjectResponse, error)
		ListProjectMembers(ctx context.Context, projectSlug string) ([]usecase.ProjectMemberResponse, error)
		AddProjectMember(ctx context.Context, projectSlug, userID, role string) (*usecase.ProjectMemberResponse, error)
		IsProjectMember(ctx context.Context, projectID, userID string) (bool, error)
		ListProjects(ctx context.Context) ([]usecase.ProjectResponse, error)
		GetProject(ctx context.Context, slug string) (*usecase.ProjectResponse, error)
		UpdateProject(ctx context.Context, slug string, name, description *string) (*usecase.ProjectResponse, error)
		DeleteProject(ctx context.Context, slug string) (*usecase.ProjectResponse, error)
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
		PreviewPatch(ctx context.Context, findingID string) (*patch.Outcome, error)
		PreviewNotification(ctx context.Context, findingID, channel, target string, alreadyLinked bool) (*notify.Outcome, error)
	}

	ReportUsecases interface {
		IngestReport(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error)
		ListReports(ctx context.Context, projectSlug string, limit, offset int32) ([]usecase.ReportResponse, error)
		GetReport(ctx context.Context, reportID string) (*usecase.ReportResponse, error)
	}

	GateUsecases interface {
		GetGateStatus(ctx context.Context, projectSlug string, minSeverityRank int16) (*usecase.GateStatusOutput, error)
		GetIntroducedGateStatus(ctx context.Context, projectSlug string, minSeverityRank int16, reportID string) (*usecase.GateStatusOutput, error)
		PreviewPRCheck(ctx context.Context, input usecase.PRCheckPreviewInput) (*usecase.PRCheckPreview, error)
	}

	AdminUsecases interface {
		GetAdminStatus(ctx context.Context) (*usecase.AdminStatus, error)
		PreviewRetention(ctx context.Context, olderThanDays int) (*usecase.RetentionPreview, error)
		PurgeRetention(ctx context.Context, olderThanDays int) (*usecase.RetentionResult, error)
	}

	PolicyUsecases interface {
		CreatePolicyTemplate(ctx context.Context, name, description string, definition json.RawMessage) (*usecase.PolicyTemplateResponse, error)
		ListPolicyTemplates(ctx context.Context) ([]usecase.PolicyTemplateResponse, error)
		UpdatePolicyTemplate(ctx context.Context, id, name, description string, definition json.RawMessage) (*usecase.PolicyTemplateResponse, error)
		DeletePolicyTemplate(ctx context.Context, id string) error
		SetProjectPolicy(ctx context.Context, projectSlug, templateName string) (*usecase.PolicyEffectiveResponse, error)
		SetProjectPolicyOverrides(ctx context.Context, projectSlug string, overrides map[string]string) (*usecase.PolicyEffectiveResponse, error)
		EffectivePolicy(ctx context.Context, projectSlug string) (*usecase.PolicyEffectiveResponse, error)
	}

	TeamUsecases interface {
		CreateTeam(ctx context.Context, name, description string) (*usecase.TeamResponse, error)
		ListTeams(ctx context.Context) ([]usecase.TeamResponse, error)
		DeleteTeam(ctx context.Context, teamID string) error
		AddTeamMember(ctx context.Context, teamID, userID, role string) (*usecase.TeamMemberResponse, error)
		ListTeamMembers(ctx context.Context, teamID string) ([]usecase.TeamMemberResponse, error)
		RemoveTeamMember(ctx context.Context, teamID, userID string) error
		LinkProjectTeam(ctx context.Context, projectSlug, teamID, role string) (*usecase.ProjectTeamResponse, error)
		UnlinkProjectTeam(ctx context.Context, projectSlug, teamID string) error
		ListProjectTeams(ctx context.Context, projectSlug string) ([]usecase.ProjectTeamResponse, error)
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
	AdminUsecases
	PolicyUsecases
	TeamUsecases
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
	Project        string          `json:"project"`
	Scanner        string          `json:"scanner"`
	ScannerVersion string          `json:"scanner_version,omitempty"`
	ParserVersion  string          `json:"parser_version,omitempty"`
	RawData        json.RawMessage `json:"raw_data"`
	Branch         string          `json:"branch,omitempty"`
	CommitSha      string          `json:"commit_sha,omitempty"`
	// BaseRevision is required when ScanMode is incremental; ChangedFiles
	// lists the paths an incremental scan covered; ScanMode is full
	// (default) or incremental.
	BaseRevision string   `json:"base_revision,omitempty"`
	ChangedFiles []string `json:"changed_files,omitempty"`
	ScanMode     string   `json:"scan_mode,omitempty"`
	// GateIntroducedOnly scopes the post-ingest threshold check to
	// findings this report introduced.
	GateIntroducedOnly bool   `json:"gate_introduced_only,omitempty"`
	GateSeverity       string `json:"gate_severity,omitempty"`
	GateStatus         string `json:"gate_status,omitempty"`
	Environment        string `json:"environment,omitempty"`
	Owner              string `json:"owner,omitempty"`
	Digest             string `json:"digest,omitempty"`
	ArtifactName       string `json:"artifact_name,omitempty"`
	ArtifactVersion    string `json:"artifact_version,omitempty"`
	ArtifactType       string `json:"artifact_type,omitempty"`
}
type ingestResponse struct {
	ReportID          string `json:"report_id"`
	TotalFindings     int    `json:"total_findings"`
	ThresholdBreached bool   `json:"threshold_breached"`
	// ScanMode is the effective mode (full, or incremental when the
	// scanner supports it and a baseline resolved); FallbackReason
	// explains a downgrade to full; Introduced/PreExistingCount split
	// the findings by change classification.
	ScanMode         string `json:"scan_mode"`
	FallbackReason   string `json:"fallback_reason,omitempty"`
	IntroducedCount  int    `json:"introduced_count"`
	PreExistingCount int    `json:"pre_existing_count"`
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

// decodeJSONBody decodes a JSON request body whose size is capped at
// maxBytes. Oversized requests — whether by declared Content-Length or by
// exceeding the cap mid-read on a chunked body — are rejected with 413
// body_too_large; malformed JSON keeps the caller's own code and message.
// It reports false when the request must not be processed further.
func decodeJSONBody(w http.ResponseWriter, r *http.Request, v any, maxBytes int64, invalidCode, invalidMsg string) bool {
	if r.Body == nil {
		respondError(w, http.StatusBadRequest, invalidCode, invalidMsg)
		return false
	}
	if r.ContentLength > maxBytes {
		respondError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
		return false
	}
	if maxBytes > 0 {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	}
	err := json.NewDecoder(r.Body).Decode(v)
	if err != nil {
		if errors.Is(err, io.EOF) {
			// Empty body: leave the zero value in place. Callers with
			// required fields validate them after decoding.
			return true
		}
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			respondError(w, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large")
			return false
		}
		respondError(w, http.StatusBadRequest, invalidCode, invalidMsg)
		return false
	}
	return true
}

// maxPageSize bounds a single paginated request; larger limits are clamped.
const maxPageSize = 500

// msgProjectNotFound is the shared not-found message for project responses.
const msgProjectNotFound = "project not found"

// Request-body size limits (M1). Ingest carries raw scanner output, so it
// gets a generous cap; every other JSON body carries small, server-derived
// fields and is capped at 1 MiB. All caps are absolute ceilings: a declared
// Content-Length above the cap is rejected up front, and bodies that arrive
// without a length (chunked) are still cut off mid-read by MaxBytesReader.
const (
	maxIngestBodyBytes = 25 << 20 // 25 MiB
	maxJSONBodyBytes   = 1 << 20  // 1 MiB
	// maxBulkFindingIDs bounds the finding_ids fan-out of BulkTriage so one
	// request cannot drive unbounded per-id lookup and update work.
	maxBulkFindingIDs = 1000
)

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

var (
	errProjectNotFound     = errors.New(msgProjectNotFound)
	errProjectAccessDenied = errors.New("project access denied")
)

func (h *Handler) respondProjectAccessError(w http.ResponseWriter, err error) {
	if errors.Is(err, errProjectNotFound) {
		respondError(w, http.StatusNotFound, "not_found", msgProjectNotFound)
		return
	}
	respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this project")
}

// enforceProjectAccess gates slug-scoped routes on tenant membership
// (H1): unauthenticated callers are denied; API keys must match the
// resolved project; global admins pass if the project exists; other session
// users must hold a membership row. The GetProject lookup itself enforces the
// same rule, so this stays consistent if either layer is reached first.
func (h *Handler) enforceProjectAccess(r *http.Request, projectSlug string) error {
	ident := auth.ContextIdentity(r.Context())
	if ident == nil {
		return errProjectAccessDenied
	}
	if ident.Role == auth.RoleAdmin {
		if h.usecase == nil {
			return nil
		}
		project, err := h.usecase.GetProject(r.Context(), projectSlug)
		if err != nil || project == nil {
			return errProjectNotFound
		}
		return nil
	}
	if h.usecase == nil {
		return errProjectAccessDenied
	}
	project, err := h.usecase.GetProject(r.Context(), projectSlug)
	if err != nil || project == nil {
		return errProjectAccessDenied
	}
	if ident.IsAPIKey {
		if project.ID != ident.ProjectID {
			return errProjectAccessDenied
		}
		return nil
	}
	ok, err := h.usecase.IsProjectMember(r.Context(), project.ID, ident.UserID)
	if err != nil || !ok {
		return errProjectAccessDenied
	}
	return nil
}

// RequireRole is a middleware that enforces a role for session-authenticated
// users and the matching permission scope for API-key principals.
//
// Session users are authorized when their JWT role is one of the demanded
// roles. The identity's role is validated against the canonical RBAC
// vocabulary (auth.ValidRole) before the demanded-role check: a token
// carrying a role outside admin/editor/viewer — the legacy DB role "member",
// an empty claim, or garbage — is not a known principal and is denied 403,
// never admitted just because no demanded role matched it.
//
// API keys are project-scoped and never carry session roles, so they cannot
// satisfy a role gate by identity: the demanded roles are mapped to the
// equivalent API-key permission scopes (admin routes → the "admin" scope),
// and a key is admitted only when it holds that scope. An authentic key with
// no matching scope is denied 403 — an ingest-only key must never reach an
// admin-gated route (creating projects, managing API keys, triage, waivers,
// global daemon state). Unauthenticated requests fall through to 401.
// apiKeyRoleAdmitted reports whether an API-key identity holds one of the
// permission scopes the role gate demands.
func apiKeyRoleAdmitted(ident *auth.Identity, requiredScopes map[string]bool) bool {
	for scope := range requiredScopes {
		if ident.HasScope(scope) {
			return true
		}
	}
	return false
}

// sessionRoleAdmitted reports whether a session identity carries a known
// role within the demanded set.
func sessionRoleAdmitted(ident *auth.Identity, allowed map[string]bool) bool {
	return auth.ValidRole(ident.Role) && allowed[ident.Role]
}

func RequireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	requiredScopes := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
		if scope, ok := auth.RoleScope(r); ok {
			requiredScopes[scope] = true
		}
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ident := auth.ContextIdentity(r.Context())
			if ident == nil {
				respondError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
				return
			}
			if !identityAdmitted(ident, allowed, requiredScopes) {
				respondRoleError(w, ident)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// identityAdmitted decides access for one identity: API keys must hold the
// permission scope the route demands, sessions must hold an allowed role.
func identityAdmitted(ident *auth.Identity, allowed, requiredScopes map[string]bool) bool {
	if ident.IsAPIKey {
		return apiKeyRoleAdmitted(ident, requiredScopes)
	}
	return sessionRoleAdmitted(ident, allowed)
}

// respondRoleError picks the refusal detail for the identity type.
func respondRoleError(w http.ResponseWriter, ident *auth.Identity) {
	if ident.IsAPIKey {
		respondError(w, http.StatusForbidden, "insufficient_scope", "API key does not have the required scope for this route")
		return
	}
	respondError(w, http.StatusForbidden, "insufficient_role", "requires admin role")
}

func (h *Handler) ListFindings(w http.ResponseWriter, r *http.Request) {
	slug := chi.URLParam(r, "slug")
	if err := h.enforceProjectAccess(r, slug); err != nil {
		h.respondProjectAccessError(w, err)
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
		respondError(w, http.StatusNotFound, "not_found", msgProjectNotFound)
		return
	}
	respondJSON(w, http.StatusOK, findings)
}

// severityRankToken maps one severity name to its gate rank (0 when unknown).
func severityRankToken(token string) int16 {
	switch strings.TrimSpace(token) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func parseMinSeverityRank(severities string) int16 {
	if severities == "" {
		return 3 // default: high+
	}
	minRank := int16(0)
	for _, p := range strings.Split(severities, ",") {
		if rank := severityRankToken(p); rank > minRank {
			minRank = rank
		}
	}
	if minRank == 0 {
		return 3
	}
	return minRank
}
