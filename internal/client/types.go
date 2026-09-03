// Package client is the typed HTTP client for the Specht API (used by the
// specht CLI and CI/CD adapters). It mirrors the server's JSON wire types:
// request payloads encode to the API contract and response structs decode
// from it.
package client

import (
	"encoding/json"
	"time"
)

// IngestPayload is the request body for ingesting a scanner report.
type IngestPayload struct {
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
	ArtifactName    string          `json:"artifact_name,omitempty"`
	ArtifactVersion string          `json:"artifact_version,omitempty"`
	ArtifactType    string          `json:"artifact_type,omitempty"`
}

// IngestResponse is the server reply to a report ingest.
type IngestResponse struct {
	ReportID          string `json:"report_id"`
	TotalFindings     int    `json:"total_findings"`
	ThresholdBreached bool   `json:"threshold_breached"`
}

// GateStatus is a project's current deployment-gate evaluation.
type GateStatus struct {
	ThresholdBreached bool     `json:"threshold_breached"`
	BlockingCount     int64    `json:"blocking_count"`
	BlockedBy         []string `json:"blocked_by,omitempty"`
	WaivedCount       int      `json:"waived_count,omitempty"`
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
}

// Report is an ingested scanner report (one scan run).
type Report struct {
	ID            string     `json:"id"`
	ProjectID     string     `json:"project_id"`
	ToolName      string     `json:"tool_name"`
	ToolVersion   *string    `json:"tool_version"`
	ScanType      string     `json:"scan_type"`
	ScanTarget    *string    `json:"scan_target"`
	Status        string     `json:"status"`
	TotalFindings *int32     `json:"total_findings"`
	Branch        *string    `json:"branch"`
	CommitSha     *string    `json:"commit_sha"`
	CreatedAt     time.Time  `json:"created_at"`
	CompletedAt   *time.Time `json:"completed_at"`
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
	Name        string                  `json:"name,omitempty"`
	Description string                  `json:"description,omitempty"`
	Conditions  []CreateWaiverCondition `json:"conditions,omitempty"`
	Contexts    []CreateWaiverContext   `json:"contexts,omitempty"`
	TargetIDs   []string                `json:"target_ids,omitempty"`
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

// APIError is the error envelope the API returns on non-2xx responses.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type apiErrorWrapper struct {
	Error APIError `json:"error"`
}
