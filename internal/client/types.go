package client

import (
	"encoding/json"
	"time"
)

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

type IngestResponse struct {
	ReportID          string `json:"report_id"`
	TotalFindings     int    `json:"total_findings"`
	ThresholdBreached bool   `json:"threshold_breached"`
}

type GateStatus struct {
	ThresholdBreached bool     `json:"threshold_breached"`
	BlockingCount     int64    `json:"blocking_count"`
	BlockedBy         []string `json:"blocked_by,omitempty"`
	WaivedCount       int      `json:"waived_count,omitempty"`
}

type Project struct {
	ID          string    `json:"id"`
	Slug        string    `json:"slug"`
	Name        string    `json:"name"`
	Description *string   `json:"description"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateProjectRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
}

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

type TriageRequest struct {
	AnalysisState     string     `json:"analysis_state"`
	Reason            string     `json:"reason,omitempty"`
	AnalysisExpiresAt *time.Time `json:"analysis_expires_at,omitempty"`
}

type TriageResponse struct {
	FindingID     string `json:"finding_id"`
	AnalysisState string `json:"analysis_state"`
	GateEffect    string `json:"gate_effect"`
}

type BulkTriageRequest struct {
	FindingIDs        []string   `json:"finding_ids"`
	AnalysisState     string     `json:"analysis_state"`
	Reason            string     `json:"reason,omitempty"`
	AnalysisExpiresAt *time.Time `json:"analysis_expires_at,omitempty"`
}

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

type AuthResponse struct {
	Token        string `json:"token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	UserID       string `json:"user_id"`
	Email        string `json:"email"`
}

type UserProfile struct {
	ID          string `json:"id"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name,omitempty"`
	Role        string `json:"role"`
	CreatedAt   string `json:"created_at"`
}

type APIKey struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	KeyPrefix string  `json:"key_prefix"`
	RawKey    string  `json:"raw_key,omitempty"`
	LastFour  *string `json:"last_four"`
	CreatedAt string  `json:"created_at"`
}

type CreateAPIKeyRequest struct {
	Name    string `json:"name"`
	Project string `json:"project"`
}

type Environment struct {
	ID              string `json:"id"`
	ProjectID       string `json:"project_id"`
	Name            string `json:"name"`
	Tier            string `json:"tier"`
	InternetFacing  bool   `json:"internet_facing"`
	DataSensitivity string `json:"data_sensitivity"`
	CreatedAt       string `json:"created_at"`
}

type Target struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
	Locator   string `json:"locator,omitempty"`
	CreatedAt string `json:"created_at"`
}

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

type WaiverCondition struct {
	ID       string `json:"id"`
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type WaiverContext struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id,omitempty"`
	TargetID      string `json:"target_id,omitempty"`
	ArtifactID    string `json:"artifact_id,omitempty"`
}

type WaiverFindingTarget struct {
	ID        string `json:"id"`
	FindingID string `json:"finding_id"`
}

type WaiverDetail struct {
	Waiver
	Conditions []WaiverCondition     `json:"conditions"`
	Contexts   []WaiverContext       `json:"contexts"`
	Targets    []WaiverFindingTarget `json:"targets"`
}

type WaiverEvent struct {
	ID        string          `json:"id"`
	WaiverID  string          `json:"waiver_id"`
	EventType string          `json:"event_type"`
	ActorID   string          `json:"actor_id,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt string          `json:"created_at"`
}

type CreateWaiverRequest struct {
	Name        string                  `json:"name"`
	Description string                  `json:"description"`
	Conditions  []CreateWaiverCondition `json:"conditions,omitempty"`
	Contexts    []CreateWaiverContext   `json:"contexts,omitempty"`
	TargetIDs   []string                `json:"target_ids,omitempty"`
}

type CreateWaiverCondition struct {
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

type CreateWaiverContext struct {
	EnvironmentID string `json:"environment_id,omitempty"`
	TargetID      string `json:"target_id,omitempty"`
	ArtifactID    string `json:"artifact_id,omitempty"`
}

type UpdateWaiverRequest struct {
	Name        string                  `json:"name,omitempty"`
	Description string                  `json:"description,omitempty"`
	Conditions  []CreateWaiverCondition `json:"conditions,omitempty"`
	Contexts    []CreateWaiverContext   `json:"contexts,omitempty"`
	TargetIDs   []string                `json:"target_ids,omitempty"`
}

type CheckWaiverMatchResponse struct {
	Matched bool `json:"matched"`
}

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type apiErrorWrapper struct {
	Error APIError `json:"error"`
}
