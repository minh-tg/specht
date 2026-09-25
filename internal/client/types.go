// Package client is the typed HTTP client for the Specht API (used by the
// specht CLI and CI/CD adapters). It mirrors the server's JSON wire types:
// request payloads encode to the API contract and response structs decode
// from it.
package client

import (
	"encoding/json"
	"time"

	"github.com/minh-tg/specht/internal/notify"
	"github.com/minh-tg/specht/internal/patch"
)

// IngestPayload is the request body for ingesting a scanner report.
type IngestPayload struct {
	Project            string          `json:"project"`
	Scanner            string          `json:"scanner"`
	ScannerVersion     string          `json:"scanner_version,omitempty"`
	ParserVersion      string          `json:"parser_version,omitempty"`
	RawData            json.RawMessage `json:"raw_data"`
	Branch             string          `json:"branch,omitempty"`
	CommitSha          string          `json:"commit_sha,omitempty"`
	BaseRevision       string          `json:"base_revision,omitempty"`
	ChangedFiles       []string        `json:"changed_files,omitempty"`
	ScanMode           string          `json:"scan_mode,omitempty"`
	GateIntroducedOnly bool            `json:"gate_introduced_only,omitempty"`
	GateSeverity       string          `json:"gate_severity,omitempty"`
	GateStatus         string          `json:"gate_status,omitempty"`
	Environment        string          `json:"environment,omitempty"`
	Owner              string          `json:"owner,omitempty"`
	Digest             string          `json:"digest,omitempty"`
	ArtifactName       string          `json:"artifact_name,omitempty"`
	ArtifactVersion    string          `json:"artifact_version,omitempty"`
	ArtifactType       string          `json:"artifact_type,omitempty"`
}

// IngestResponse is the server reply to a report ingest.
type IngestResponse struct {
	ReportID          string `json:"report_id"`
	TotalFindings     int    `json:"total_findings"`
	ThresholdBreached bool   `json:"threshold_breached"`
	ScanMode          string `json:"scan_mode"`
	FallbackReason    string `json:"fallback_reason,omitempty"`
	IntroducedCount   int    `json:"introduced_count"`
	PreExistingCount  int    `json:"pre_existing_count"`
}

// GateStatus is a project's current deployment-gate evaluation.
type GateStatus struct {
	ThresholdBreached bool     `json:"threshold_breached"`
	BlockingCount     int64    `json:"blocking_count"`
	BlockedBy         []string `json:"blocked_by,omitempty"`
	// BlockedByReachability maps each blocked finding id to its latest
	// reachability state.
	BlockedByReachability map[string]string `json:"blocked_by_reachability,omitempty"`
	WaivedCount           int               `json:"waived_count,omitempty"`
}

// PRCheckAnnotation is one planned pull-request annotation.
type PRCheckAnnotation struct {
	ExternalID string `json:"external_id"`
	FindingID  string `json:"finding_id"`
	File       string `json:"file"`
	StartLine  int    `json:"start_line"`
	EndLine    int    `json:"end_line"`
	Level      string `json:"level"`
	Title      string `json:"title"`
	Message    string `json:"message"`
}

// PRCheckPreview is a publishable pull-request check plan (preview only,
// never published by this client).
type PRCheckPreview struct {
	Provider      string              `json:"provider"`
	CommitSha     string              `json:"commit_sha"`
	ReportID      string              `json:"report_id,omitempty"`
	Conclusion    string              `json:"conclusion"`
	Title         string              `json:"title"`
	Summary       string              `json:"summary"`
	Annotations   []PRCheckAnnotation `json:"annotations"`
	SummaryCounts map[string]int      `json:"summary_counts"`
	Truncated     bool                `json:"truncated"`
	TotalMappable int                 `json:"total_mappable"`
	Supersedes    string              `json:"supersedes,omitempty"`
	WaivedCount   int                 `json:"waived_count"`
}

// PatchOutcome aliases the patch planning outcome: a supported proposal
// or an explicit refusal (never a partial patch).
type PatchOutcome = patch.Outcome

// PatchProposal aliases one reviewable remediation proposal.
type PatchProposal = patch.Proposal

// NotifyOutcome aliases the notification planning outcome: a supported
// plan or an explicit refusal (never a partial plan).
type NotifyOutcome = notify.Outcome

// NotifyPlan aliases one reviewable notification action.
type NotifyPlan = notify.Plan

// AdminStatus is the platform observability snapshot for admins.
type AdminStatus struct {
	Projects              int64      `json:"projects"`
	Users                 int64      `json:"users"`
	OpenFindings          int64      `json:"open_findings"`
	Reports               int64      `json:"reports"`
	OldestSettledReportAt *time.Time `json:"oldest_settled_report_at"`
}

// RetentionPreview counts settled reports a purge would delete.
type RetentionPreview struct {
	OlderThanDays int       `json:"older_than_days"`
	Cutoff        time.Time `json:"cutoff"`
	StaleReports  int64     `json:"stale_reports"`
}

// RetentionResult reports what a purge deleted.
type RetentionResult struct {
	OlderThanDays    int       `json:"older_than_days"`
	Cutoff           time.Time `json:"cutoff"`
	DeletedReports   int64     `json:"deleted_reports"`
	DeletedReportIDs []string  `json:"deleted_report_ids,omitempty"`
	Truncated        bool      `json:"truncated,omitempty"`
}

// PolicyTemplate is a reusable organization-wide policy baseline.
type PolicyTemplate struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Definition  map[string]string `json:"definition"`
	Version     int32             `json:"version"`
}

// PolicyEffective is one project's resolved policy with provenance.
type PolicyEffective struct {
	TemplateName    *string `json:"template_name"`
	TemplateVersion int     `json:"template_version"`
	SeverityFloor   string  `json:"severity_floor"`
	SeveritySource  string  `json:"severity_source"`
	WatcherGate     string  `json:"watcher_gate"`
	WatcherSource   string  `json:"watcher_source"`
}

// Team is a named group of users that projects link for access.
type Team struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// TeamMember binds a user to a team.
type TeamMember struct {
	TeamID    string `json:"team_id"`
	UserID    string `json:"user_id"`
	UserEmail string `json:"user_email,omitempty"`
	Role      string `json:"role"`
}

// ProjectTeam links a team to a project with the conferred role.
type ProjectTeam struct {
	ProjectID string `json:"project_id"`
	TeamID    string `json:"team_id"`
	TeamName  string `json:"team_name"`
	Role      string `json:"role"`
}

// Project is a scan project (the top-level tenant of findings and reports).
type Project struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description *string   `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// CreateProjectRequest is the request body for creating a project.
type CreateProjectRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
}

// Finding is a deduplicated vulnerability finding within a project.
type Finding struct {
	ID              string    `json:"id"`
	ProjectID       string    `json:"project_id"`
	FindingKind     string    `json:"finding_kind"`
	Fingerprint     string    `json:"fingerprint"`
	CurrentTitle    string    `json:"current_title"`
	CurrentSeverity string    `json:"current_severity"`
	CurrentScore    *float64  `json:"current_score"`
	State           string    `json:"state"`
	TriageStatus    string    `json:"triage_status"`
	AnalysisState   string    `json:"analysis_state"`
	GateEffect      string    `json:"gate_effect"`
	FirstSeenAt     time.Time `json:"first_seen_at"`
	LastSeenAt      time.Time `json:"last_seen_at"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	// IntroducedByReportID and IntroducedCommitSha carry
	// introduced-by-change attribution; both nil means unattributed.
	IntroducedByReportID *string `json:"introduced_by_report_id,omitempty"`
	IntroducedCommitSha  *string `json:"introduced_commit_sha,omitempty"`
}

// Report is an ingested scanner report (one scan run).
type Report struct {
	ID            string  `json:"id"`
	ProjectID     string  `json:"project_id"`
	ToolName      string  `json:"tool_name"`
	ToolVersion   *string `json:"tool_version"`
	ScanType      string  `json:"scan_type"`
	ScanTarget    *string `json:"scan_target"`
	Status        string  `json:"status"`
	TotalFindings *int32  `json:"total_findings"`
	Branch        *string `json:"branch"`
	CommitSha     *string `json:"commit_sha"`
	// BaseRevision, ScanMode, and ChangedFiles describe incremental
	// analysis context.
	BaseRevision *string    `json:"base_revision,omitempty"`
	ScanMode     string     `json:"scan_mode,omitempty"`
	ChangedFiles []string   `json:"changed_files,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	CompletedAt  *time.Time `json:"completed_at"`
}

// TriageRequest is the request body for setting a finding's analysis state.
type TriageRequest struct {
	AnalysisState     string     `json:"analysis_state"`
	Reason            string     `json:"reason,omitempty"`
	AnalysisExpiresAt *time.Time `json:"analysis_expires_at,omitempty"`
}

// TriageResponse reports the triage outcome for one finding.
type TriageResponse struct {
	FindingID     string `json:"finding_id"`
	AnalysisState string `json:"analysis_state"`
	GateEffect    string `json:"gate_effect"`
}

// BulkTriageRequest applies one analysis state to many findings at once.
type BulkTriageRequest struct {
	FindingIDs        []string   `json:"finding_ids"`
	AnalysisState     string     `json:"analysis_state"`
	Reason            string     `json:"reason,omitempty"`
	AnalysisExpiresAt *time.Time `json:"analysis_expires_at,omitempty"`
}

// FindingEvent is an audit event recorded against a finding.
type FindingEvent struct {
	ID        string    `json:"id"`
	FindingID string    `json:"finding_id"`
	UserID    string    `json:"user_id"`
	EventType string    `json:"event_type"`
	OldValue  *string   `json:"old_value,omitempty"`
	NewValue  *string   `json:"new_value,omitempty"`
	Comment   *string   `json:"comment,omitempty"`
	Changes   []byte    `json:"changes,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// AuthResponse carries the tokens and identity returned by login/register.
type AuthResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
}

// UserProfile is the authenticated user's profile.
type UserProfile struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role"`
	CreatedAt   string `json:"created_at"`
}

// APIKey is a project-scoped API key. RawKey is only present in the create
// response (the server stores only a hash).
type APIKey struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	KeyPrefix string  `json:"key_prefix"`
	RawKey    string  `json:"raw_key,omitempty"`
	LastFour  *string `json:"last_four"`
	CreatedAt string  `json:"created_at"`
}

// Evidence is an evidence artifact attached to a finding.
type Evidence struct {
	ID          string  `json:"id"`
	FindingID   string  `json:"finding_id"`
	Type        string  `json:"type"`
	URL         string  `json:"url"`
	Description string  `json:"description"`
	UploadedBy  *string `json:"uploaded_by"`
	CreatedAt   string  `json:"created_at"`
}

// ScannerDescriptor is the API representation of a scanner capability.
type ScannerDescriptor struct {
	Name                  string   `json:"name"`
	Version               string   `json:"version"`
	FindingKinds          []string `json:"finding_kinds"`
	ScanTypes             []string `json:"scan_types"`
	ProvidesPackages      bool     `json:"provides_packages"`
	SupportsAutoDetection bool     `json:"supports_auto_detection"`
}

// CreateAPIKeyRequest is the request body for minting an API key.
type CreateAPIKeyRequest struct {
	Name    string `json:"name"`
	Project string `json:"project"`
}

// Environment is a deployment environment a project scans against.
type Environment struct {
	ID              string `json:"id"`
	ProjectID       string `json:"project_id"`
	Name            string `json:"name"`
	Tier            string `json:"tier"`
	InternetFacing  bool   `json:"internet_facing"`
	DataSensitivity string `json:"data_sensitivity"`
	CreatedAt       string `json:"created_at"`
}

// Target is a scan target (repo, image, filesystem, etc.) within a project.
type Target struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Locator   string `json:"locator,omitempty"`
	CreatedAt string `json:"created_at"`
}

// Artifact is a specific artifact (image digest, package build) of a target.
type Artifact struct {
	ID           string `json:"id"`
	ProjectID    string `json:"project_id"`
	TargetID     string `json:"target_id,omitempty"`
	ArtifactType string `json:"artifact_type"`
	Name         string `json:"name"`
	Version      string `json:"version,omitempty"`
	Digest       string `json:"digest,omitempty"`
	Locator      string `json:"locator,omitempty"`
	CreatedAt    string `json:"created_at"`
}

// Waiver is a waiver policy with its conditions, contexts, and targets.
type Waiver struct {
	ID          string                `json:"id"`
	ProjectID   string                `json:"project_id"`
	Name        string                `json:"name"`
	Description string                `json:"description"`
	Enabled     bool                  `json:"enabled"`
	ExpiresAt   string                `json:"expires_at,omitempty"`
	Conditions  []WaiverCondition     `json:"conditions"`
	Contexts    []WaiverContext       `json:"contexts"`
	Targets     []WaiverFindingTarget `json:"targets"`
	CreatedAt   string                `json:"created_at"`
	UpdatedAt   string                `json:"updated_at"`
}

// WaiverCondition is a predicate on a finding field.
type WaiverCondition struct {
	ID       string `json:"id"`
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// WaiverContext scopes a waiver to environments/targets/artifacts.
type WaiverContext struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id,omitempty"`
	TargetID      string `json:"target_id,omitempty"`
	ArtifactID    string `json:"artifact_id,omitempty"`
}

// WaiverFindingTarget pins a waiver to one specific finding.
type WaiverFindingTarget struct {
	ID        string `json:"id"`
	FindingID string `json:"finding_id"`
}

// WaiverDetail is a waiver plus its full condition/context/target rows.
type WaiverDetail struct {
	Waiver
	Conditions []WaiverCondition     `json:"conditions"`
	Contexts   []WaiverContext       `json:"contexts"`
	Targets    []WaiverFindingTarget `json:"targets"`
}

// WaiverEvent is an audit event recorded against a waiver.
type WaiverEvent struct {
	ID        string          `json:"id"`
	WaiverID  string          `json:"waiver_id"`
	EventType string          `json:"event_type"`
	ActorID   string          `json:"actor_id,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt string          `json:"created_at"`
}

// CreateWaiverRequest is the request body for creating a waiver.
type CreateWaiverRequest struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	ExpiresAt   string                  `json:"expires_at,omitempty"`
	Conditions  []CreateWaiverCondition `json:"conditions,omitempty"`
	Contexts    []CreateWaiverContext   `json:"contexts,omitempty"`
	TargetIDs   []string                `json:"target_ids,omitempty"`
}

// CreateWaiverCondition is a condition input for waiver creation.
type CreateWaiverCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// CreateWaiverContext is a context input for waiver creation.
type CreateWaiverContext struct {
	EnvironmentID string `json:"environment_id,omitempty"`
	TargetID      string `json:"target_id,omitempty"`
	ArtifactID    string `json:"artifact_id,omitempty"`
}

// UpdateWaiverRequest is the request body for updating a waiver.
type UpdateWaiverRequest struct {
	Name        string `json:"name,omitempty"`
	Description string `json:"description,omitempty"`
	// ExpiresAt is the update tri-state: nil omits the field (keep the
	// stored expiry), a pointer to "" clears it, an RFC3339 value sets it.
	// A plain string with omitempty could not express "clear", which is
	// why this is a pointer.
	ExpiresAt  *string                 `json:"expires_at,omitempty"`
	Conditions []CreateWaiverCondition `json:"conditions,omitempty"`
	Contexts   []CreateWaiverContext   `json:"contexts,omitempty"`
	TargetIDs  []string                `json:"target_ids,omitempty"`
}

// CheckWaiverMatchResponse reports whether a single finding is waived.
type CheckWaiverMatchResponse struct {
	Matched bool `json:"matched"`
}

// LoginRequest is the request body for email/password login.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RegisterRequest is the request body for self-service registration.
type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// RefreshRequest is the request body for rotating a refresh token.
type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

// SeverityCount is one severity bucket of a project's finding breakdown.
type SeverityCount struct {
	Severity      string `json:"severity"`
	Count         int32  `json:"count"`
	BlockingCount int32  `json:"blocking_count"`
}

// ProjectStats is a project's aggregate finding/waiver/report statistics.
type ProjectStats struct {
	TotalFindings int32           `json:"total_findings"`
	BlockingCount int32           `json:"blocking_count"`
	WaiverCount   int32           `json:"waiver_count"`
	ReportCount   int32           `json:"report_count"`
	BySeverity    []SeverityCount `json:"by_severity"`
	LatestReport  *Report         `json:"latest_report,omitempty"`
}

// AgingBucketCount is one age bucket with its overdue subset.
type AgingBucketCount struct {
	Bucket  string `json:"bucket"`
	Count   int32  `json:"count"`
	Overdue int32  `json:"overdue"`
}

// OverdueFinding is an open finding past its SLA date.
type OverdueFinding struct {
	ID       string    `json:"id"`
	Title    string    `json:"title"`
	Severity string    `json:"severity"`
	AgeDays  int32     `json:"age_days"`
	SLADays  int32     `json:"sla_days"`
	DueDate  time.Time `json:"due_date"`
	Reopened bool      `json:"reopened"`
}

// AgingResponse is a project's aging/SLA snapshot.
type AgingResponse struct {
	Buckets      []AgingBucketCount `json:"buckets"`
	OverdueTotal int32              `json:"overdue_total"`
	Overdue      []OverdueFinding   `json:"overdue"`
	Reopened     int32              `json:"reopened"`
	NewPerWeek   []WeeklyNew        `json:"new_per_week"`
}

// WeeklyNew is one week's newly introduced finding count.
type WeeklyNew struct {
	Week  string `json:"week"`
	Count int32  `json:"count"`
}

// VerifyResponse is the outcome of evidence-backed fix verification.
type VerifyResponse struct {
	FindingID string  `json:"finding_id"`
	Outcome   string  `json:"outcome"`
	ReportID  *string `json:"report_id,omitempty"`
	Detail    string  `json:"detail"`
}

// APIError is the error envelope the API returns on non-2xx responses.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type apiErrorWrapper struct {
	Error APIError `json:"error"`
}

// ReachabilityAssessment is a finding's human reachability assessment.
type ReachabilityAssessment struct {
	ID         string `json:"id"`
	FindingID  string `json:"finding_id"`
	State      string `json:"state"`
	Evidence   string `json:"evidence"`
	AssessedBy string `json:"assessed_by"`
	CreatedAt  string `json:"created_at"`
	UpdatedAt  string `json:"updated_at"`
}

// UpsertReachabilityRequest sets a finding's reachability assessment.
type UpsertReachabilityRequest struct {
	State    string `json:"state"`
	Evidence string `json:"evidence"`
}

// WatcherStatus is the CVE watcher daemon's health.
type WatcherStatus struct {
	LastSuccessfulPollAt string `json:"last_successful_poll_at,omitempty"`
	LastPollAttemptAt    string `json:"last_poll_attempt_at,omitempty"`
	LastError            string `json:"last_error,omitempty"`
	ConsecutiveFailures  int32  `json:"consecutive_failures"`
	Healthy              bool   `json:"healthy"`
	Stale                bool   `json:"stale"`
	StalenessWindow      string `json:"staleness_window,omitempty"`
}
