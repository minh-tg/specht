// Package port defines the neutral application contracts between the core
// (use cases, lifecycle, watcher) and persistence/auth providers. Ports use
// domain DTOs, string IDs (validated at the adapter boundary), time.Time,
// json.RawMessage, and primitive slices only — no sqlc, pgtype, or
// *pgxpool.Pool leaks across this seam. internal/repo implements these ports
// over PostgreSQL; an in-memory fake exercises the same contracts in unit
// tests.
//
// The port set deliberately mirrors the current repository capabilities.
// Atomic multi-row operations live in purpose-specific methods (waiver
// create/update with child rows, watcher finding persistence) rather than a
// generic WithTx(func(*sqlc.Queries)) handle.
package port

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

// ErrNotFound is returned by port methods when a row does not exist. The
// Postgres adapter maps pgx.ErrNoRows to it at the boundary.
var ErrNotFound = errors.New("not found")

// ErrDuplicateReport is returned when a report with the same raw-content
// hash has already been ingested for the project.
var ErrDuplicateReport = errors.New("duplicate report")

// ErrFindingSuppressed is returned by the watcher finding persist path when
// the finding fingerprint already exists (a re-poll hit) and no row changed.
var ErrFindingSuppressed = errors.New("finding already exists")

// ---------- Projects ----------

// Project is the neutral project row.
type Project struct {
	ID                     string
	Slug                   string
	Name                   string
	Description            *string
	DeploymentThreshold    string
	CveWatcherGate         string
	CveWatcherEnabled      bool
	CveWatcherIntervalSecs int32
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// CreateProjectInput carries the create-project fields.
type CreateProjectInput struct {
	Slug                string
	Name                string
	Description         string
	DeploymentThreshold string
	Settings            json.RawMessage
}

// ProjectStore is the consumer-facing project persistence contract.
// ProjectMember binds a user to a project with a project-scoped role.
// Membership is the tenant-isolation boundary (H1): session principals must
// hold a membership row for every project they access.
type ProjectMember struct {
	ProjectID string
	UserID    string
	Role      string
	CreatedAt time.Time
}

type ProjectStore interface {
	Create(ctx context.Context, input CreateProjectInput) (Project, error)
	List(ctx context.Context) ([]Project, error)
	GetBySlug(ctx context.Context, slug string) (Project, error)
	GetByID(ctx context.Context, id string) (Project, error)
	Update(ctx context.Context, slug, name string, description *string) (Project, error)
	Delete(ctx context.Context, slug string) (Project, error)
	UpsertMember(ctx context.Context, projectID, userID, role string) (ProjectMember, error)
	ListMembers(ctx context.Context, projectID string) ([]ProjectMember, error)
	IsMember(ctx context.Context, projectID, userID string) (bool, error)
}

// ---------- Users ----------

// User is the neutral user row.
type User struct {
	ID           string
	Email        string
	DisplayName  *string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

// UserStore persists user accounts.
type UserStore interface {
	Create(ctx context.Context, email string, displayName, passwordHash *string) (User, error)
	GetByEmail(ctx context.Context, email string) (User, error)
	GetByID(ctx context.Context, id string) (User, error)
	// SetRole changes a user's global role (admin elevation path for H1
	// tenant administration). Role must be a valid users.role value.
	SetRole(ctx context.Context, userID, role string) (User, error)
	// UpdateDisplayName changes a user's display name. A nil displayName
	// clears it.
	UpdateDisplayName(ctx context.Context, userID string, displayName *string) (User, error)
}

// ---------- Refresh tokens ----------

// RefreshToken is a persisted refresh-token row.
type RefreshToken struct {
	ID        string
	UserID    string
	TokenHash string
	ExpiresAt time.Time
	RevokedAt *time.Time
}

// RefreshTokenStore persists refresh tokens.
type RefreshTokenStore interface {
	Create(ctx context.Context, userID, tokenHash string, expiresAt time.Time) (RefreshToken, error)
	GetByHash(ctx context.Context, tokenHash string) (RefreshToken, error)
	Revoke(ctx context.Context, id string) (RefreshToken, error)
	RevokeAllForUser(ctx context.Context, userID string) error
}

// ---------- API keys ----------

// APIKey is a project-scoped API key row.
type APIKey struct {
	ID         string
	ProjectID  string
	Name       string
	KeyPrefix  string
	LastFour   *string
	CreatedBy  *string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
	LastUsedAt *time.Time
	RevokedAt  *time.Time
}

// CreateAPIKeyInput carries create fields (hash is only ever stored).
type CreateAPIKeyInput struct {
	ProjectID string
	Name      string
	KeyPrefix string
	KeyHash   string
	LastFour  string
	Scopes    json.RawMessage
	CreatedBy string
	ExpiresAt *time.Time
}

// APIKeyStore persists project API keys.
type APIKeyStore interface {
	Create(ctx context.Context, input CreateAPIKeyInput) (APIKey, error)
	ListByProject(ctx context.Context, projectID string) ([]APIKey, error)
	GetByHash(ctx context.Context, keyHash string) (APIKey, error)
	Revoke(ctx context.Context, id, projectID string) (APIKey, error)
	// TouchLastUsed stamps last_used_at on an active (unrevoked) key.
	TouchLastUsed(ctx context.Context, id string) error
}

// ---------- Environments ----------

// Environment is a deployment environment row.
type Environment struct {
	ID              string
	ProjectID       string
	Name            string
	Tier            string
	InternetFacing  bool
	DataSensitivity string
	CreatedAt       time.Time
}

// EnvironmentStore persists deployment environments.
type EnvironmentStore interface {
	Upsert(ctx context.Context, projectID, name, tier string, internetFacing bool, dataSensitivity string) (Environment, error)
	List(ctx context.Context, projectID string) ([]Environment, error)
	GetByID(ctx context.Context, id, projectID string) (Environment, error)
	Delete(ctx context.Context, id, projectID string) (Environment, error)
}

// ---------- Targets ----------

// Target is a scan target row.
type Target struct {
	ID        string
	ProjectID string
	Name      string
	Kind      string
	Locator   *string
	// Owner is the repository owner identity in provider://owner/repo URI
	// format. nil when no owner was supplied. last supplied wins.
	Owner *string

	CreatedAt time.Time
}

type TargetStore interface {
	// Upsert inserts or updates a target. An empty owner preserves the
	// stored value; a non-empty owner overwrites it (last supplied wins).
	// Owner is expected in provider://owner/repo URI format.
	Upsert(ctx context.Context, projectID, name, kind, locator, owner string) (Target, error)
	List(ctx context.Context, projectID string) ([]Target, error)
	GetByID(ctx context.Context, id, projectID string) (Target, error)
	Delete(ctx context.Context, id, projectID string) (Target, error)
}

// ---------- Artifacts ----------

// Artifact is an artifact row of a scan target.
type Artifact struct {
	ID           string
	ProjectID    string
	TargetID     string
	ArtifactType string
	Name         string
	Version      *string
	Digest       *string
	Locator      *string
	Metadata     json.RawMessage
	CreatedAt    time.Time
}

// ArtifactStore persists artifacts of scan targets.
type ArtifactStore interface {
	Upsert(ctx context.Context, input ArtifactInput) (Artifact, error)
	List(ctx context.Context, projectID string) ([]Artifact, error)
	ListByTarget(ctx context.Context, targetID string) ([]Artifact, error)
	GetByID(ctx context.Context, id, projectID string) (Artifact, error)
	Delete(ctx context.Context, id, projectID string) (Artifact, error)
}

// ArtifactInput carries artifact upsert fields.
type ArtifactInput struct {
	ProjectID    string
	TargetID     string
	ArtifactType string
	Name         string
	Version      *string
	Digest       *string
	Locator      *string
	Metadata     json.RawMessage
}

// ---------- Waivers ----------

// Waiver is a waiver policy row.
type Waiver struct {
	ID          string
	ProjectID   string
	Name        string
	Description string
	Enabled     bool
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// WaiverCondition is one waiver predicate.
type WaiverCondition struct {
	ID       string
	Field    string
	Operator string
	Value    string
}

// WaiverContext is one waiver scope. Empty IDs are wildcards.
type WaiverContext struct {
	ID            string
	EnvironmentID string
	TargetID      string
	ArtifactID    string
}

// WaiverFindingTarget pins a waiver to a finding.
type WaiverFindingTarget struct {
	ID        string
	FindingID string
}

// WaiverEvent is a waiver audit event.
type WaiverEvent struct {
	ID        string
	WaiverID  string
	EventType string
	ActorID   string
	Metadata  json.RawMessage
	CreatedAt time.Time
}

// WaiverChildInput describes the condition/context/target children to write.
type WaiverChildInput struct {
	Condition WaiverCondition
	Context   WaiverContext
	Target    WaiverFindingTarget
}

// WaiverEventInput carries the audit event for unit-of-work methods.
type WaiverEventInput struct {
	EventType string
	ActorID   *string
	Metadata  json.RawMessage
}

// WaiverStore persists waivers and their children/events atomically.
type WaiverStore interface {
	CreateWithDetails(ctx context.Context, projectID, name, description string, enabled bool, conditions []WaiverCondition, contexts []WaiverContext, targets []WaiverFindingTarget, event WaiverEventInput) (Waiver, error)
	List(ctx context.Context, projectID string) ([]Waiver, error)
	GetByID(ctx context.Context, id, projectID string) (Waiver, error)
	UpdateWithDetails(ctx context.Context, waiver Waiver, conditions *[]WaiverCondition, contexts *[]WaiverContext, targets *[]WaiverFindingTarget, event WaiverEventInput) (Waiver, error)
	Delete(ctx context.Context, id, projectID string) error
	Toggle(ctx context.Context, id, projectID string) (Waiver, error)
	ListActive(ctx context.Context, projectID string) ([]Waiver, error)
	ListConditions(ctx context.Context, waiverID string) ([]WaiverCondition, error)
	ListContexts(ctx context.Context, waiverID string) ([]WaiverContext, error)
	ListFindingTargets(ctx context.Context, waiverID string) ([]WaiverFindingTarget, error)
	CreateEvent(ctx context.Context, event WaiverEvent) error
	ListEvents(ctx context.Context, waiverID string) ([]WaiverEvent, error)
}

// ---------- Findings ----------

// Finding is the neutral finding row.
type Finding struct {
	ID                  string
	ProjectID           string
	FindingKind         string
	Fingerprint         string
	CurrentTitle        string
	CurrentSeverity     string
	CurrentSeverityRank int16
	CurrentScore        *float64
	State               string
	TriageStatus        string
	AnalysisState       string
	GateEffect          string
	AnalysisExpiresAt   *time.Time
	AnalysisReason      *string
	AnalysisSource      string
	ManualOverride      bool
	ReviewRequired      bool
	FingerprintVersion  int32
	FirstSeenAt         time.Time
	LastSeenAt          time.Time
	CreatedAt           time.Time
	UpdatedAt           time.Time
}

// Occurrence is one finding occurrence row.
type Occurrence struct {
	ID           string
	FindingID    string
	ReportID     *string
	Title        string
	Severity     string
	SeverityRank int16
	ToolName     string
	ObservedAt   time.Time
}

// OccurrenceInput carries occurrence create fields.
type OccurrenceInput struct {
	FindingID       string
	ReportID        *string
	Title           string
	Description     *string
	Severity        string
	SeverityRank    int16
	Score           float64
	ToolName        string
	ToolVersion     *string
	ParserVersion   *string
	LocationSummary *string
	SubjectSummary  *string
	Remediation     *string
	Display         json.RawMessage
	Metadata        json.RawMessage
	ObservedAt      time.Time
}

// DimensionInput is one finding dimension row.
type DimensionInput struct {
	FindingID string
	Key       string
	Value     string
	Source    *string
}

// FindingDimension is one persisted dimension of a finding.
type FindingDimension struct {
	Key   string
	Value string
}

// FindingEvent is one finding audit event.
type FindingEvent struct {
	ID        string
	FindingID string
	UserID    *string
	EventType string
	OldValue  *string
	NewValue  *string
	Comment   *string
	Changes   json.RawMessage
	CreatedAt time.Time
}

// FindingEventInput carries audit-event create fields.
type FindingEventInput struct {
	FindingID string
	UserID    *string
	EventType string
	OldValue  *string
	NewValue  *string
	Comment   *string
	Changes   json.RawMessage
}

// UpdateAnalysisInput carries the analysis-state update fields.
type UpdateAnalysisInput struct {
	ID                string
	AnalysisState     string
	GateEffect        string
	AnalysisExpiresAt *time.Time
	AnalysisReason    *string
	AnalysisSource    string
	ManualOverride    bool
	ReviewRequired    bool
	AnalysisUpdatedBy *string
}

// FindingStore persists findings, occurrences, dimensions, events, and the
// watcher finding unit-of-work.
type FindingStore interface {
	Upsert(ctx context.Context, projectID, findingKind, fingerprint, title, severity string, severityRank int16, score float64, firstSeen, lastSeen time.Time) (Finding, error)
	GetByID(ctx context.Context, id string) (Finding, error)
	GetByFingerprint(ctx context.Context, projectID, findingKind, fingerprint string) (Finding, error)
	ListByIDs(ctx context.Context, ids []string) ([]Finding, error)
	ListByProject(ctx context.Context, projectID string, severities, states, kinds, environments, targets []string, limit, offset int32) ([]Finding, error)
	UpdateAnalysis(ctx context.Context, input UpdateAnalysisInput) (Finding, error)
	BulkUpdateAnalysis(ctx context.Context, input UpdateAnalysisInput, ids []string) ([]Finding, error)
	CreateEvent(ctx context.Context, input FindingEventInput) (FindingEvent, error)
	ListEvents(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]FindingEvent, error)
	// ListDimensions returns every persisted dimension of a finding,
	// ordered by key for determinism.
	ListDimensions(ctx context.Context, findingID string) ([]FindingDimension, error)
	// HasOccurrence reports whether a finding was observed in a report.
	HasOccurrence(ctx context.Context, findingID, reportID string) (bool, error)
	// MarkFixed moves a finding to the scan-derived fixed state. It is
	// the only path to fixed: triage never sets it, only VerifyFix does,
	// backed by a rescan that no longer observes the finding.
	MarkFixed(ctx context.Context, findingID string) (Finding, error)
	HasDimension(ctx context.Context, findingID, key string) (bool, error)
	CreateOccurrence(ctx context.Context, input OccurrenceInput) (Occurrence, error)
	UpsertDimension(ctx context.Context, input DimensionInput) error
	GetFindingContext(ctx context.Context, findingID string) (FindingContext, error)
	// GetFindingDisplayContext returns the latest observed deployment
	// context of a finding for detail views: target, environment, branch,
	// and commit names. Every field is empty when the context is missing —
	// missing context is explicit, never a placeholder string.
	GetFindingDisplayContext(ctx context.Context, findingID string) (FindingDisplayContext, error)
	ListBlockingFindings(ctx context.Context, projectID string, minSeverityRank int16) ([]Finding, error)
	// ListGateCandidates loads every gate candidate with its context and
	// latest reachability in one batch (kills the per-finding N+1 context
	// lookups). Reachability is empty when no assessment exists.
	ListGateCandidates(ctx context.Context, projectID string, minSeverityRank int16) ([]GateCandidate, error)
	FindScaFindingIDForPurlAndCve(ctx context.Context, projectID, purlName string, candidateIDs []string) (string, error)

	// Watcher unit-of-work: insert the finding and its dependent rows
	// atomically. Returns ErrFindingSuppressed when the fingerprint already
	// exists (re-poll hit).
	PersistWatcherFinding(ctx context.Context, input PersistWatcherFindingInput) (Finding, error)
	// PersistWatcherSkipEvent appends an audit event to the suppressing
	// finding.
	PersistWatcherSkipEvent(ctx context.Context, findingID string, event FindingEventInput) error
}

// FindingContext is the environment/target/artifact context of a finding.
type FindingContext struct {
	EnvironmentID string
	TargetID      string
	ArtifactID    string
}

// FindingDisplayContext is the human-readable deployment context of a
// finding's latest observation, for detail views and routing.
type FindingDisplayContext struct {
	TargetName      string
	TargetKind      string
	TargetOwner     string
	EnvironmentName string
	Branch          string
	CommitSha       string
	// ToolName is the scanner that produced the latest observation.
	ToolName string
	// LocationSummary is the latest observed location string.
	LocationSummary string
	// Metadata is the latest occurrence metadata document (specht
	// namespace carries fix, code location, resource).
	Metadata json.RawMessage
}

// GateCandidate is a finding that may block a project's gate together with
// its deployment context and latest reachability assessment, loaded in one
// batch. The SQL candidate query is a performance prefilter only;
// gate.Gate.Evaluate is authoritative.
type GateCandidate struct {
	Finding
	Context      FindingContext
	Reachability string
}

// PersistWatcherFindingInput carries one watcher finding unit-of-work.
type PersistWatcherFindingInput struct {
	Finding    Finding
	Dimensions []DimensionInput
	Occurrence OccurrenceInput
	Event      *FindingEventInput
	Evidence   *EvidenceInput
}

// ---------- Evidence ----------

// Evidence is an evidence artifact row.
type Evidence struct {
	ID          string
	FindingID   string
	Type        string
	URL         string
	Description string
	UploadedBy  *string
	CreatedAt   time.Time
}

// EvidenceInput carries evidence create fields.
type EvidenceInput struct {
	FindingID   string
	Type        string
	URL         string
	Description string
	UploadedBy  *string
}

// EvidenceStore persists evidence artifacts.
type EvidenceStore interface {
	Create(ctx context.Context, input EvidenceInput) (Evidence, error)
	ListByFinding(ctx context.Context, findingID string) ([]Evidence, error)
	GetByID(ctx context.Context, id string) (Evidence, error)
	Delete(ctx context.Context, id string) error
}

// ---------- Reachability ----------

// ReachabilityAssessment is one assessment row.
type ReachabilityAssessment struct {
	ID         string
	FindingID  string
	State      string
	Evidence   string
	AssessedBy string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// ReachabilityStore persists reachability assessments.
type ReachabilityStore interface {
	Upsert(ctx context.Context, findingID, state, evidence, assessedBy string) (ReachabilityAssessment, error)
	ListByFinding(ctx context.Context, findingID string) ([]ReachabilityAssessment, error)
	GetByID(ctx context.Context, id string) (ReachabilityAssessment, error)
	LatestByFinding(ctx context.Context, findingID string) (ReachabilityAssessment, error)
	LatestByFindings(ctx context.Context, findingIDs []string) ([]ReachabilityAssessment, error)
}

// ---------- Signoffs ----------

// Signoff is a signoff record.
type Signoff struct {
	ID         string
	FindingID  string
	Status     string
	ReviewedBy string
	Comment    string
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

// SignoffStore persists finding signoffs.
type SignoffStore interface {
	Upsert(ctx context.Context, findingID, status, reviewedBy, comment string) (Signoff, error)
	GetByFinding(ctx context.Context, findingID string) (Signoff, error)
}

// ---------- Reports ----------

// Report is an ingested scan report row.
type Report struct {
	ID            string
	ProjectID     string
	ToolName      string
	ToolVersion   *string
	ScanType      string
	ScanTarget    *string
	Status        string
	TotalFindings *int32
	Branch        *string
	CommitSha     *string
	CreatedAt     time.Time
	CompletedAt   *time.Time
}

// CreateReportInput carries report create fields.
type CreateReportInput struct {
	ProjectID        string
	ToolName         string
	ToolVersion      *string
	ScanType         string
	ScanTarget       *string
	TargetID         string
	ArtifactID       string
	EnvironmentID    string
	ScanScope        json.RawMessage
	ScanScopeHash    string
	Branch           *string
	CommitSha        *string
	RawData          json.RawMessage
	RawReportHash    string
	ParserVersion    *string
	ScanCompleteness string
	Status           string
}

// ReportStore persists scan reports.
type ReportStore interface {
	Create(ctx context.Context, input CreateReportInput) (Report, error)
	GetByID(ctx context.Context, id string) (Report, error)
	ListByProject(ctx context.Context, projectID string, limit, offset int32) ([]Report, error)
	UpdateStatus(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMessage *string) (Report, error)
	// LatestCompletedByScanner returns the newest completed report from
	// one scanner, or ErrNotFound when the scanner never completed.
	LatestCompletedByScanner(ctx context.Context, projectID, scanner string) (CompletedReport, error)
}

// CompletedReport is the verification basis: the newest completed scan
// from one scanner with its revision and scope completeness.
type CompletedReport struct {
	ID           string
	ToolName     string
	Branch       *string
	CommitSha    *string
	Completeness string
	CreatedAt    time.Time
}

// ---------- Inventory ----------

// PackageRef is one inventory row.
type PackageRef struct {
	PURL         string
	Ecosystem    *string
	Name         *string
	Version      *string
	ManifestPath *string
}

// InventoryPackage is a distinct inventory row for the watcher's package view.
type InventoryPackage struct {
	PURL      string
	Name      string
	Version   string
	Ecosystem string
	Manifest  string
}

// InventoryStore persists report package inventory.
type InventoryStore interface {
	UpsertReportPackages(ctx context.Context, reportID string, packages []PackageRef) error
	DistinctInventory(ctx context.Context, projectID string, since time.Duration) ([]InventoryPackage, error)
	DeleteReportPackages(ctx context.Context, reportID string) error
}

// ---------- Stats ----------

// SeverityStat is one severity bucket of project stats.
type SeverityStat struct {
	Severity      string
	Count         int32
	BlockingCount int32
}

// StatsStore serves aggregate project statistics.
type StatsStore interface {
	GetProjectStats(ctx context.Context, projectID string) ([]SeverityStat, error)
	GetProjectWaiverCount(ctx context.Context, projectID string) (int32, error)
	GetProjectReportCount(ctx context.Context, projectID string) (int32, error)
	GetProjectLatestReport(ctx context.Context, projectID string) (Report, error)
	// GetAgingRows loads every finding's aging input for a project,
	// oldest first, capped at 10000 rows.
	GetAgingRows(ctx context.Context, projectID string) ([]AgingRow, error)
}

// AgingRow is one finding's aging input: identity, severity, first
// observation, lifecycle state, and whether it ever reopened.
type AgingRow struct {
	ID           string
	Title        string
	Severity     string
	SeverityRank int
	FirstSeen    time.Time
	State        string
	Reopened     bool
}

// ---------- Watcher ----------

// WatcherState is the global watcher health row.
type WatcherState struct {
	LastSuccessfulPollAt *time.Time
	LastPollAttemptAt    *time.Time
	LastError            *string
	ConsecutiveFailures  int32
}

// WatcherProjectState is a project's own watermark.
type WatcherProjectState struct {
	ProjectID            string
	LastSuccessfulPollAt *time.Time
}

// WatcherStore persists the watcher watermark/health rows.
type WatcherStore interface {
	GetState(ctx context.Context) (WatcherState, error)
	UpdateState(ctx context.Context, ts time.Time) error
	RecordAttempt(ctx context.Context, ts time.Time) error
	RecordFailure(ctx context.Context, errText string, ts time.Time) error
	ResetFailure(ctx context.Context) error
	GetProjectConfig(ctx context.Context, projectID string) (Project, error)
	GetProjectState(ctx context.Context, projectID string) (WatcherProjectState, error)
	UpsertProjectState(ctx context.Context, projectID string, ts time.Time) error
}

// ---------- Aggregate ----------

// Stores is the aggregate persistence handle the core depends on. It is the
// port counterpart of repo.Repos.
type Stores struct {
	Projects      ProjectStore
	Users         UserStore
	RefreshTokens RefreshTokenStore
	APIKeys       APIKeyStore
	Environments  EnvironmentStore
	Targets       TargetStore
	Artifacts     ArtifactStore
	Waivers       WaiverStore
	Findings      FindingStore
	Evidence      EvidenceStore
	Reachability  ReachabilityStore
	Signoffs      SignoffStore
	Reports       ReportStore
	Inventory     InventoryStore
	Stats         StatsStore
	Watcher       WatcherStore
}

// AnalysisExpiryStore is the persistence surface for the analysis-expiry
// sweep: find expired findings and reset them to unanalyzed/block inside the
// same transaction the caller drives through Do.
type AnalysisExpiryStore interface {
	// ExpireExpired runs one transaction that finds findings whose analysis
	// window expired, resets each to unanalyzed/block, logs the
	// analysis_changed event, and reports the findings it reset.
	ExpireExpired(ctx context.Context) ([]Finding, error)
}

// WaiverExpiryStore is the persistence surface for the waiver-expiry sweep.
type WaiverExpiryStore interface {
	// ExpireExpired runs one transaction that disables expired waivers and
	// logs their auto_disabled events, returning the disabled waivers.
	ExpireExpired(ctx context.Context) ([]Waiver, error)
}
