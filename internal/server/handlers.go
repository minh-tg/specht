package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/go-chi/chi/v5/middleware"
	"github.com/minh-tg/specht/internal/audit"
	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/notify"
	"github.com/minh-tg/specht/internal/patch"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/reqctx"
	"github.com/minh-tg/specht/internal/usecase"
)

// AuthMiddleware authenticates requests, trying each authenticator in order and storing the identity on the context.
func AuthMiddleware(authenticators ...auth.Authenticator) func(http.Handler) http.Handler {
	return AuthMiddlewareLimited(nil, authenticators...)
}

// AuthMiddlewareLimited is AuthMiddleware plus a per-IP budget for requests
// that present credentials and fail: a request with an Authorization header
// skips the pre-auth limiter (a valid one is judged by the per-caller limiter
// after this middleware), so the budget has to be spent here, once the header
// is known to be bad. When the budget is gone the caller gets 429 instead of
// 401. A nil failures limiter makes it AuthMiddleware.
func AuthMiddlewareLimited(failures *RateLimiter, authenticators ...auth.Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			header := r.Header.Get("Authorization")
			if len(header) < 7 || !strings.EqualFold(header[:7], "Bearer ") {
				rejectCredentials(w, r, failures, "missing_token", "authorization header required")
				return
			}
			token := strings.TrimSpace(header[7:])

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

				rejectCredentials(w, r, failures, "invalid_token", "invalid or expired token")
				return
			}

			rejectCredentials(w, r, failures, "invalid_token", "invalid or expired token")
		})
	}
}

// rejectCredentials answers 401, or 429 when the caller's address has used up
// its budget for rejected credentials. A request without an Authorization
// header was already counted by the pre-auth limiter and is not counted twice.
func rejectCredentials(w http.ResponseWriter, r *http.Request, failures *RateLimiter, code, message string) {
	if failures != nil && r.Header.Get("Authorization") != "" {
		if limiter := failures.limiterFor("ip:"+clientHost(r), failures.now()); !limiter.Allow() {
			writeRateLimited(w, limiter)
			return
		}
	}
	respondError(w, http.StatusUnauthorized, code, message)
}

// LoggerMiddleware writes one line per request, when it finishes: request id,
// method, status, duration, bytes and caller. It logs the route pattern, never
// the raw path or query, because those can hold single-use tokens (an invite
// link) or text an attacker chose. Server errors log at error level, the
// liveness and readiness probes at debug so they do not drown the log.
func LoggerMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := reqctx.Start(r.Context())
		if start.IsZero() {
			start = time.Now()
		}
		ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
		next.ServeHTTP(ww, r)

		status := ww.Status()
		if status == 0 {
			status = http.StatusOK
		}
		route := unmatchedRoute
		if rc := chi.RouteContext(r.Context()); rc != nil && rc.RoutePattern() != "" {
			route = rc.RoutePattern()
		}
		level := slog.LevelInfo
		switch {
		case status >= http.StatusInternalServerError:
			level = slog.LevelError
		case route == "/api/v1/health" || route == "/api/v1/ready":
			level = slog.LevelDebug
		}
		slog.Log(r.Context(), level, "request",
			"request_id", reqctx.ID(r.Context()),
			"method", r.Method,
			"route", route,
			"status", status,
			"duration_ms", time.Since(start).Milliseconds(),
			"bytes", ww.BytesWritten(),
			"remote", r.RemoteAddr,
		)
	})
}

// unmatchedRoute stands in for the route of a request no handler claimed, so
// a scanner's chosen path never reaches the log.
const unmatchedRoute = "(unmatched)"

type (
	AuthUsecases interface {
		Register(ctx context.Context, email, password string) (*usecase.AuthResponse, error)
		Login(ctx context.Context, email, password string) (*usecase.AuthResponse, error)
		FindOrProvisionSSOUser(ctx context.Context, claims auth.SSOClaims, allowedDomains []string, adminGroups []string) (userID, role string, provisioned bool, err error)
		CreateSSOExchangeCode(ctx context.Context, userID, browserBinding string) (string, error)
		ExchangeSSOCode(ctx context.Context, code string, presented []auth.PresentedLogin) (*usecase.AuthResponse, auth.PresentedLogin, error)
		Refresh(ctx context.Context, refreshToken string) (*usecase.AuthResponse, error)
		Logout(ctx context.Context, refreshToken string) error
		GetProfile(ctx context.Context, userID string) (*usecase.UserProfile, error)
		UpdateProfile(ctx context.Context, userID string, displayName *string) (*usecase.UserProfile, error)
		ChangePassword(ctx context.Context, userID, current, next string) (*usecase.AuthResponse, error)
		CreatePasswordResetLink(ctx context.Context, userID string) (*usecase.PasswordResetLinkResponse, error)
		RedeemPasswordReset(ctx context.Context, token, password string) error
		ListUsers(ctx context.Context, filter string, limit, offset int32) ([]usecase.UserProfile, error)
		SetupRequired(ctx context.Context) (bool, error)
		Setup(ctx context.Context, input usecase.SetupInput) (*usecase.AuthResponse, error)
		CreateInvite(ctx context.Context, projectSlug string, in usecase.CreateInviteInput) (*usecase.InviteResponse, error)
		ListInvites(ctx context.Context, projectSlug string) ([]usecase.InviteResponse, error)
		RevokeInvite(ctx context.Context, projectSlug, inviteID string) (*usecase.InviteResponse, error)
		LookupInvite(ctx context.Context, token string) (*usecase.InviteLookupResponse, error)
		AcceptInvite(ctx context.Context, token string, in usecase.AcceptInviteInput) (*usecase.AcceptInviteResponse, error)
		JoinInvite(ctx context.Context, token string) (*usecase.JoinInviteResponse, error)
		DeleteReport(ctx context.Context, projectSlug, reportID string) (*usecase.ReportDeleteResponse, error)
		GetProjectWatcher(ctx context.Context, projectSlug string) (*usecase.ProjectWatcherResponse, error)
		UpdateProjectWatcher(ctx context.Context, projectSlug string, in usecase.WatcherSettingsInput) (*usecase.ProjectWatcherResponse, error)
		ChangeUserRole(ctx context.Context, userID, role string) (*usecase.UserProfile, error)
		DeactivateUser(ctx context.Context, userID string, force bool) (*usecase.UserProfile, []usecase.RevokedAPIKey, error)
		ReactivateUser(ctx context.Context, userID string) (*usecase.UserProfile, error)
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
		AddProjectMemberByEmail(ctx context.Context, projectSlug, email, role string) (*usecase.ProjectMemberResponse, error)
		SuggestProjectMembers(ctx context.Context, projectSlug, query string, directoryClosed bool) ([]usecase.MemberSuggestion, error)
		RemoveProjectMember(ctx context.Context, projectSlug, userID string) error
		IsProjectMember(ctx context.Context, projectID, userID string) (bool, error)
		ListProjects(ctx context.Context) ([]usecase.ProjectResponse, error)
		GetProject(ctx context.Context, slug string) (*usecase.ProjectResponse, error)
		UpdateProject(ctx context.Context, slug string, name, description *string) (*usecase.ProjectResponse, error)
		DeleteProject(ctx context.Context, slug string) (*usecase.ProjectResponse, error)
		ListEnvironments(ctx context.Context, projectSlug string) ([]usecase.EnvironmentResponse, error)
		UpdateEnvironment(ctx context.Context, in usecase.UpdateEnvironmentInput) (*usecase.EnvironmentResponse, error)
		ListTargets(ctx context.Context, projectSlug string) ([]usecase.TargetResponse, error)
		ListArtifacts(ctx context.Context, projectSlug string) ([]usecase.ArtifactResponse, error)
	}

	FindingUsecases interface {
		ListFindings(ctx context.Context, projectSlug string, filter usecase.FindingFilter, limit, offset int32) ([]usecase.FindingResponse, int64, error)
		GetFinding(ctx context.Context, findingID string) (*usecase.FindingResponse, error)
		TriageFinding(ctx context.Context, input usecase.TriageInput) (*usecase.TriageOutput, error)
		UndoTriage(ctx context.Context, input usecase.UndoTriageInput) (*usecase.TriageOutput, error)
		VerifyFix(ctx context.Context, findingID string) (*usecase.VerifyResponse, error)
		BulkTriage(ctx context.Context, input usecase.BulkTriageInput) ([]usecase.TriageOutput, error)
		GetFindingEvents(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]usecase.FindingEvent, error)
		PreviewPatch(ctx context.Context, findingID string) (*patch.Outcome, error)
		PreviewNotification(ctx context.Context, findingID, channel, target string, alreadyLinked bool) (*notify.Outcome, error)
	}

	ReportUsecases interface {
		AuthorizeIngest(ctx context.Context, projectSlug string) error
		IngestReport(ctx context.Context, input usecase.IngestReportInput) (*usecase.IngestReportOutput, error)
		ListReports(ctx context.Context, projectSlug string, filter usecase.ReportFilter, limit, offset int32) ([]usecase.ReportResponse, error)
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
		AddTeamMemberByEmail(ctx context.Context, teamID, email, role string) (*usecase.TeamMemberResponse, error)
		ListTeamMembers(ctx context.Context, teamID string) ([]usecase.TeamMemberResponse, error)
		RemoveTeamMember(ctx context.Context, teamID, userID string) error
		LinkProjectTeam(ctx context.Context, projectSlug, teamID, role string) (*usecase.ProjectTeamResponse, error)
		UnlinkProjectTeam(ctx context.Context, projectSlug, teamID string) error
		ListProjectTeams(ctx context.Context, projectSlug string) ([]usecase.ProjectTeamResponse, error)
	}

	WaiverUsecases interface {
		CreateWaiver(ctx context.Context, input usecase.CreateWaiverInput) (*usecase.WaiverResponse, error)
		ListWaivers(ctx context.Context, projectSlug string, statuses ...string) ([]usecase.WaiverResponse, error)
		RequestWaiver(ctx context.Context, input usecase.RequestWaiverInput) (*usecase.WaiverResponse, error)
		ApproveWaiver(ctx context.Context, projectSlug, waiverID, note string) (*usecase.WaiverResponse, error)
		RejectWaiver(ctx context.Context, projectSlug, waiverID, note string) (*usecase.WaiverResponse, error)
		WithdrawWaiver(ctx context.Context, projectSlug, waiverID string) (*usecase.WaiverResponse, error)
		GetWaiver(ctx context.Context, projectSlug, waiverID string) (*usecase.WaiverDetailResponse, error)
		UpdateWaiver(ctx context.Context, input usecase.UpdateWaiverInput) (*usecase.WaiverResponse, error)
		DeleteWaiver(ctx context.Context, projectSlug, waiverID string) error
		ToggleWaiver(ctx context.Context, projectSlug, waiverID, actorID string) (*usecase.WaiverResponse, error)
		RevokeWaiver(ctx context.Context, projectSlug, waiverID, actorID string, expectedUpdatedAt *time.Time) (*usecase.WaiverResponse, error)
		RestoreWaiver(ctx context.Context, projectSlug, waiverID, actorID string, expectedUpdatedAt *time.Time) (*usecase.WaiverResponse, error)
		ListWaiverEvents(ctx context.Context, projectSlug, waiverID string) ([]usecase.WaiverEventResp, error)
		CheckWaiverMatch(ctx context.Context, projectSlug, findingID string) (bool, error)
	}

	EvidenceUsecases interface {
		CreateEvidence(ctx context.Context, findingID, userID, typ, url, description string) (usecase.EvidenceResponse, error)
		ListEvidence(ctx context.Context, findingID string) ([]usecase.EvidenceResponse, error)
		DeleteEvidence(ctx context.Context, findingID, evidenceID string) error
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
	revoker auth.TokenRevoker
	// loginDelay slows repeated failed password logins per account. Nil
	// disables it.
	loginDelay *loginDelay
	// ingest is the admission control for report ingests: concurrency slots,
	// the memory budget and the per-caller gates. NewHandler installs the
	// defaults and NewRouter replaces them with the configured limits.
	ingest *ingestAdmission
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
	CVEUsecases
}

// NewHandler builds the HTTP handlers over a use-case implementation.
func NewHandler(uc usecaseInterface, revokers ...auth.TokenRevoker) *Handler {
	var revoker auth.TokenRevoker
	if len(revokers) > 0 {
		revoker = revokers[0]
	}
	return &Handler{
		usecase: uc,
		audit:   audit.NewLogger(nil),
		revoker: revoker,
		ingest:  newIngestAdmission(0, 0, defaultIngestQueueWait),
	}
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
	// Replayed is true when the request matched an already completed report
	// for the same project, bytes, and commit; the response then carries that
	// report's id and a freshly evaluated verdict, at HTTP 200.
	Replayed bool `json:"replayed"`
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

// respondJSONConditional answers 200 with a weak ETag derived from the body,
// or 304 with no body when the client already holds that version. A poller
// then costs one read and no payload while nothing changed.
func respondJSONConditional(w http.ResponseWriter, r *http.Request, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		log.Printf("encode response: %v", err)
		respondError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		return
	}
	sum := sha256.Sum256(body)
	etag := `W/"` + hex.EncodeToString(sum[:16]) + `"`
	w.Header().Set("ETag", etag)
	if etagMatches(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(append(body, '\n')); err != nil {
		log.Printf("write response: %v", err)
	}
}

// etagMatches reports whether an If-None-Match header lists etag (weak
// comparison) or the wildcard.
func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || strings.TrimPrefix(candidate, "W/") == strings.TrimPrefix(etag, "W/") {
			return true
		}
	}
	return false
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

// Request-body size limits. Ingest carries raw scanner output, so it
// gets a generous cap; every other JSON body carries small, server-derived
// fields and is capped at 1 MiB. All caps are absolute ceilings: a declared
// Content-Length above the cap is rejected up front, and bodies that arrive
// without a length (chunked) are still cut off mid-read by MaxBytesReader.
const (
	maxIngestBodyBytes = 25 << 20 // 25 MiB
	maxJSONBodyBytes   = 1 << 20  // 1 MiB
	// maxBulkFindingIDs bounds the finding_ids fan-out of BulkTriage so one
	// request cannot drive unbounded per-id lookup and update work. The use
	// case enforces the same limit for callers that do not come through here.
	maxBulkFindingIDs = usecase.MaxBulkTriageFindings
)

func parseIntParam(r *http.Request, name string, defaultVal int32) int32 {
	n := parseInt32Param(r, name, defaultVal)
	if n > maxPageSize {
		return maxPageSize
	}
	return n
}

// parseOffsetParam preserves the requested skip count instead of applying the
// page-size ceiling. The int32 bound matches sqlc's PostgreSQL OFFSET argument.
func parseOffsetParam(r *http.Request, name string, defaultVal int32) int32 {
	return parseInt32Param(r, name, defaultVal)
}

func parseInt32Param(r *http.Request, name string, defaultVal int32) int32 {
	val := r.URL.Query().Get(name)
	if val == "" {
		return defaultVal
	}
	// Parse with 32-bit size so values PostgreSQL cannot represent fall back
	// instead of wrapping to a negative offset or LIMIT -1 (unbounded rows).
	n, err := strconv.ParseInt(val, 10, 32)
	if err != nil || n < 0 {
		return defaultVal
	}
	return int32(n)
}

// queryList reads a list-valued query parameter. It accepts the name repeated
// (?type=a&type=b) and comma-separated values (?type=a,b), trims each value and
// drops blanks. It returns nil when nothing is left, which callers treat as no filter.
func queryList(r *http.Request, name string) []string {
	var out []string
	for _, raw := range r.URL.Query()[name] {
		for _, part := range strings.Split(raw, ",") {
			if part = strings.TrimSpace(part); part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

var (
	errProjectNotFound     = errors.New(msgProjectNotFound)
	errProjectAccessDenied = errors.New("project access denied")
)

// respondProjectAccessError answers a failed project access check. A missing
// project is a 404 only for global admins; everyone else gets the same 403, so
// the status never reveals whether an invisible project exists. The wording
// follows the credential: a project key is told about its key, a signed-in
// user is not.
func (h *Handler) respondProjectAccessError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, errProjectNotFound) {
		respondError(w, http.StatusNotFound, "not_found", msgProjectNotFound)
		return
	}
	respondAccessDenied(w, r, "project")
}

// respondAccessDenied answers a denied check on a project-scoped resource.
// resource names the thing being refused ("project", "finding", "report").
// Every caller gets a 403 with the same code. The message follows the
// credential: a project key is told it lacks access to the resource, while a
// signed-in user gets wording that also fits a resource that does not exist.
func respondAccessDenied(w http.ResponseWriter, r *http.Request, resource string) {
	if ident := auth.ContextIdentity(r.Context()); ident != nil && ident.IsAPIKey {
		respondError(w, http.StatusForbidden, "project_access_denied", "API key does not have access to this "+resource)
		return
	}
	respondError(w, http.StatusForbidden, "project_access_denied", resource+" not found or you do not have access")
}

// enforceProjectAccess gates slug-scoped routes on tenant membership
// unauthenticated callers are denied; API keys must match the
// resolved project; global admins pass if the project exists; other session
// users must hold a membership row. The GetProject lookup itself enforces the
// same rule, so this stays consistent if either layer is reached first.
func (h *Handler) enforceProjectAccess(r *http.Request, projectSlug string) error {
	_, err := h.projectAccess(r, projectSlug)
	return err
}

// projectAccess is enforceProjectAccess that also returns the id of the
// project it resolved, for callers that keep per-project state. The id is
// empty only when the handler has no use cases and the caller is an admin.
func (h *Handler) projectAccess(r *http.Request, projectSlug string) (string, error) {
	ident := auth.ContextIdentity(r.Context())
	if ident == nil {
		return "", errProjectAccessDenied
	}
	if ident.Role == auth.RoleAdmin {
		if h.usecase == nil {
			return "", nil
		}
		project, err := h.usecase.GetProject(r.Context(), projectSlug)
		if err != nil || project == nil {
			return "", errProjectNotFound
		}
		return project.ID, nil
	}
	if h.usecase == nil {
		return "", errProjectAccessDenied
	}
	project, err := h.usecase.GetProject(r.Context(), projectSlug)
	if err != nil || project == nil {
		return "", errProjectAccessDenied
	}
	if ident.IsAPIKey {
		if project.ID != ident.ProjectID {
			return "", errProjectAccessDenied
		}
		return project.ID, nil
	}
	ok, err := h.usecase.IsProjectMember(r.Context(), project.ID, ident.UserID)
	if err != nil || !ok {
		return "", errProjectAccessDenied
	}
	return project.ID, nil
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
// equivalent API-key permission scopes (viewer routes map to the "read"
// scope; admin, manager and editor routes map to none), and a key is admitted
// only when it holds a mapped scope. An authentic key with no matching scope
// is denied 403. Platform-wide operations such as project creation and global
// administration use RequireSessionRole instead. Unauthenticated requests
// fall through to 401.
// apiKeyRoleAdmitted reports whether an API-key identity holds one of the
// permission scopes the role gate demands.
func hasAnyScope(ident *auth.Identity, scopes map[string]bool) bool {
	for scope := range scopes {
		if ident.HasScope(scope) {
			return true
		}
	}
	return false
}

func apiKeyRoleAdmitted(ident *auth.Identity, requiredScopes map[string]bool) bool {
	return hasAnyScope(ident, requiredScopes)
}

func respondAuthRequired(w http.ResponseWriter) {
	respondError(w, http.StatusUnauthorized, "unauthorized", "authentication required")
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
				respondAuthRequired(w)
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

// RequireAPIKeyScopes restricts project-scoped API keys to any one of the
// listed scopes. Session identities pass through for project-membership
// checks in the handler or use case.
func RequireAPIKeyScopes(scopes ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		allowed[scope] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ident := auth.ContextIdentity(r.Context())
			if ident == nil {
				respondAuthRequired(w)
				return
			}
			if ident.IsAPIKey && !hasAnyScope(ident, allowed) {
				respondError(w, http.StatusForbidden, "insufficient_scope", "API key does not have the required scope for this route")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireSession excludes project-scoped API keys from user or organization
// endpoints whose authority cannot be represented by a project key.
func RequireSession() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ident := auth.ContextIdentity(r.Context())
			if ident == nil {
				respondAuthRequired(w)
				return
			}
			if ident.IsAPIKey || !auth.ValidRole(ident.Role) {
				respondError(w, http.StatusForbidden, "insufficient_role", "session authentication required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireSessionRole enforces a role for session identities only. It is used
// for platform-wide operations that a project-scoped admin key must not reach.
func RequireSessionRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, role := range roles {
		allowed[role] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ident := auth.ContextIdentity(r.Context())
			if ident == nil {
				respondAuthRequired(w)
				return
			}
			if ident.IsAPIKey || !sessionRoleAdmitted(ident, allowed) {
				respondError(w, http.StatusForbidden, "insufficient_role", "requires admin session")
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
		h.respondProjectAccessError(w, r, err)
		return
	}
	limit := parseIntParam(r, "limit", 20)
	offset := parseOffsetParam(r, "offset", 0)

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
	if s := r.URL.Query().Get("analysis_state"); s != "" {
		filter.AnalysisStates = strings.Split(s, ",")
	}
	filter.Search = r.URL.Query().Get("q")
	filter.Sort = r.URL.Query().Get("sort")
	filter.Dir = r.URL.Query().Get("dir")

	findings, total, err := h.usecase.ListFindings(r.Context(), slug, filter, limit, offset)
	if err != nil {
		if errors.Is(err, usecase.ErrInvalidFindingQuery) {
			respondError(w, http.StatusBadRequest, "invalid_query", err.Error())
			return
		}
		log.Printf("list findings: %v", err)
		if errors.Is(err, port.ErrNotFound) {
			respondError(w, http.StatusNotFound, "not_found", msgProjectNotFound)
		} else {
			respondError(w, http.StatusInternalServerError, "internal_error", "internal server error")
		}
		return
	}
	// X-Total-Count carries the size of the filtered set so a client can
	// render "n of m" and page counts; the body stays a bare array.
	w.Header().Set("X-Total-Count", strconv.FormatInt(total, 10))
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

// parseMinSeverityRank resolves a comma-separated severity list to the
// blocking floor: the LOWEST severity named, so every listed severity blocks.
// Unknown tokens are ignored; an empty or wholly unknown list floors at the
// default of high.
func parseMinSeverityRank(severities string) int16 {
	if severities == "" {
		return 3 // default: high+
	}
	minRank := int16(0)
	for _, p := range strings.Split(severities, ",") {
		rank := severityRankToken(p)
		if rank == 0 {
			continue
		}
		if minRank == 0 || rank < minRank {
			minRank = rank
		}
	}
	if minRank == 0 {
		return 3
	}
	return minRank
}
