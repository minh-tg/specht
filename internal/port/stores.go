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

// ErrAnalysisConflict is returned when an analysis write is refused because
// the finding no longer matches the state the caller based it on.
var ErrAnalysisConflict = errors.New("analysis state changed")

// ErrWaiverNotPending is returned when a waiver decision targets a waiver
// that already has a final status.
var ErrWaiverNotPending = errors.New("waiver is not pending")

// ErrWaiverNotApproved is returned when a revoke, restore or toggle targets a
// waiver that is not approved, so it has nothing to switch on or off.
var ErrWaiverNotApproved = errors.New("only an approved waiver can be revoked or restored")

// ErrWaiverChanged is returned when a conditional revoke or restore finds the
// waiver changed since the caller loaded it.
var ErrWaiverChanged = errors.New("the waiver changed since you loaded it")

// ErrWaiverLapsed is returned when a waiver would be switched on after its
// expiry has passed.
var ErrWaiverLapsed = errors.New("the waiver has expired; extend its expiry first")

// ErrLastAdmin is returned when a membership write would remove or demote the
// only remaining admin of a project. The Postgres adapter enforces it under a
// per-project lock so concurrent writes cannot both pass the check.
var ErrLastAdmin = errors.New("last project admin")

// ErrSetupClosed is returned when first-run setup is attempted after an
// admin exists.
var ErrSetupClosed = errors.New("setup is closed")

// ErrInviteEmailMismatch is returned when an invite is bound to another address.
var ErrInviteEmailMismatch = errors.New("invite is for another email address")

// ErrReportProcessing is returned when a report cannot be deleted because a
// scan is still writing it.
var ErrReportProcessing = errors.New("report is still processing")

// ErrEmailTaken is returned when a new account's email already belongs to one.
var ErrEmailTaken = errors.New("email already registered")

// ErrLastGlobalAdmin is returned when a role change or deactivation would
// leave the instance without an active global admin.
var ErrLastGlobalAdmin = errors.New("last global admin")

// ErrDuplicateReport is returned when a report with the same raw-content
// hash has already been ingested for the project.
var ErrDuplicateReport = errors.New("duplicate report")

// ErrSlugTaken is returned when a project slug already exists. The
// Postgres adapter maps the unique-violation at the boundary.
var ErrSlugTaken = errors.New("slug already taken")

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
	CveWatcherEnabled      bool
	CveWatcherIntervalSecs int32
	// Settings carries namespaced project configuration; the "policy"
	// object holds per-key policy overrides.
	Settings         json.RawMessage
	PolicyTemplateID *string
	CreatedAt        time.Time
	UpdatedAt        time.Time
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
// Membership is the tenant-isolation boundary: session principals must
// hold a membership row for every project they access.
type ProjectMember struct {
	ProjectID string
	UserID    string
	Role      string
	CreatedAt time.Time
	// Email and DisplayName name the person. Only ListMembers fills them.
	Email       string
	DisplayName string
}

type ProjectStore interface {
	Create(ctx context.Context, input CreateProjectInput) (Project, error)
	List(ctx context.Context) ([]Project, error)
	ListByIDs(ctx context.Context, ids []string) ([]Project, error)
	GetBySlug(ctx context.Context, slug string) (Project, error)
	GetByID(ctx context.Context, id string) (Project, error)
	Update(ctx context.Context, slug, name string, description *string) (Project, error)
	Delete(ctx context.Context, slug string) (Project, error)
	// UpdateSettings replaces the namespaced project configuration
	// document (policy overrides live under "policy").
	UpdateSettings(ctx context.Context, projectID string, settings json.RawMessage) (Project, error)
	UpsertMember(ctx context.Context, projectID, userID, role string) (ProjectMember, error)
	GetMember(ctx context.Context, projectID, userID string) (ProjectMember, error)
	DeleteMember(ctx context.Context, projectID, userID string) error
	CountAdmins(ctx context.Context, projectID string) (int, error)
	ListMembers(ctx context.Context, projectID string) ([]ProjectMember, error)
	IsMember(ctx context.Context, projectID, userID string) (bool, error)
	// ListMemberProjectIDs returns the IDs of all projects a user belongs
	// to in a single query (batch alternative to per-project IsMember).
	ListMemberProjectIDs(ctx context.Context, userID string) ([]string, error)
	// IsMemberEffective reports direct OR team-conferred membership: the
	// single choke point for session-user project access.
	IsMemberEffective(ctx context.Context, projectID, userID string) (bool, error)
	// ListAccessibleProjectIDs returns every project a user reaches
	// directly or through a team, for the batched list path.
	ListAccessibleProjectIDs(ctx context.Context, userID string) ([]string, error)
	// EffectiveRole returns the strongest role a user holds on a project
	// across direct membership and team links (admin > editor > viewer),
	// or ErrNotFound when the user has no access at all.
	EffectiveRole(ctx context.Context, projectID, userID string) (string, error)
}

// ---------- Users ----------

// User is the neutral user row.
type User struct {
	ID           string
	Email        string
	DisplayName  *string
	PasswordHash string
	Role         string
	// DisabledAt is set while the account is deactivated: it keeps its
	// history and memberships but cannot sign in.
	DisabledAt *time.Time
	CreatedAt  time.Time
}

// UserStore persists user accounts.
type UserStore interface {
	Create(ctx context.Context, email string, displayName, passwordHash *string) (User, error)
	GetByEmail(ctx context.Context, email string) (User, error)
	GetByID(ctx context.Context, id string) (User, error)
	// List returns accounts ordered by email. filter matches a
	// case-insensitive substring of the email; empty lists every account.
	List(ctx context.Context, filter string, limit, offset int32) ([]User, error)
	// Count returns the number of accounts.
	Count(ctx context.Context) (int64, error)
	// CountAdmins returns the number of active global admins.
	CountAdmins(ctx context.Context) (int64, error)
	// CreateFirstAdmin creates the first account as a global admin. It returns
	// ErrSetupClosed when an active admin already exists, including when
	// another request created it a moment earlier, and ErrEmailTaken when the
	// address already belongs to an account. Accounts that are not admins do
	// not close it.
	CreateFirstAdmin(ctx context.Context, email string, displayName *string, passwordHash string) (User, error)
	// SetRole changes a user's global role. Role must be a valid users.role value.
	SetRole(ctx context.Context, userID, role string) (User, error)
	// ChangeRole changes a user's global role, starts a new token generation
	// so open sessions pick the role up, and refuses to remove the last
	// active admin with ErrLastGlobalAdmin.
	ChangeRole(ctx context.Context, userID, role string) (User, error)
	// SetDisabled deactivates or reactivates an account. Deactivating starts a
	// new token generation and refuses to remove the last active admin with
	// ErrLastGlobalAdmin.
	SetDisabled(ctx context.Context, userID string, disabled bool) (User, error)
	// ClearPassword removes the account's password hash so it can no longer
	// sign in with a password. It is idempotent.
	ClearPassword(ctx context.Context, userID string) error
	// ListByIDs returns the accounts with the given ids in one query. Ids that
	// are malformed or unknown are skipped.
	ListByIDs(ctx context.Context, ids []string) ([]User, error)
	// SetPassword replaces the account's password hash and starts a new token
	// generation in one statement, so every open access token stops working.
	SetPassword(ctx context.Context, userID, passwordHash string) error
	// TokenVersion returns the account's current access-token generation.
	TokenVersion(ctx context.Context, userID string) (int32, error)
	// BumpTokenVersion invalidates every access token issued before the call.
	BumpTokenVersion(ctx context.Context, userID string) error
	// UpdateDisplayName changes a user's display name. A nil displayName
	// clears it.
	UpdateDisplayName(ctx context.Context, userID string, displayName *string) (User, error)
	// SuggestMembers returns up to limit active accounts, ordered by email, whose
	// email or any display-name word starts with prefix (case-insensitive, taken
	// literally). The system account and direct members of projectID are left out.
	SuggestMembers(ctx context.Context, projectID, prefix string, limit int32) ([]User, error)
}

// ---------- External identities ----------

// ErrIdentityLinked is returned when linking would break the one-to-one rule:
// the provider subject already belongs to an account, or the account already
// has an identity at that provider.
var ErrIdentityLinked = errors.New("identity already linked")

// UserIdentity links an account to its identity at an external provider. The
// pair (Issuer, Subject) is the stable identifier of a person at that
// provider; an email claim is not.
type UserIdentity struct {
	ID        string
	UserID    string
	Issuer    string
	Subject   string
	CreatedAt time.Time
}

// IdentityStore persists the links between accounts and provider identities.
type IdentityStore interface {
	// GetBySubject returns the identity for a provider subject, or ErrNotFound.
	GetBySubject(ctx context.Context, issuer, subject string) (UserIdentity, error)
	// GetForUser returns the identity an account has at issuer, or ErrNotFound.
	GetForUser(ctx context.Context, userID, issuer string) (UserIdentity, error)
	// Link attaches a provider identity to an account. It fails with
	// ErrIdentityLinked when either side is already linked at that provider.
	Link(ctx context.Context, userID, issuer, subject string) (UserIdentity, error)
}

// ---------- SSO exchange codes ----------

// SSOCode is a short-lived authorization code minted after successful OIDC login
// and consumed by the SPA in exchange for session and refresh tokens.
type SSOCode struct {
	CodeHash  string
	UserID    string
	ExpiresAt time.Time
}

// SSOCodeStore persists single-use SSO exchange codes.
type SSOCodeStore interface {
	Create(ctx context.Context, codeHash, userID string, expiresAt time.Time) error
	Consume(ctx context.Context, codeHash string, now time.Time) (SSOCode, error)
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
	// Ensure creates the environment with these defaults, or returns the
	// stored row unchanged. It never overwrites, so a scan that names an
	// environment cannot undo an edit.
	Ensure(ctx context.Context, projectID, name, tier string, internetFacing bool, dataSensitivity string) (Environment, error)
	List(ctx context.Context, projectID string) ([]Environment, error)
	GetByID(ctx context.Context, id, projectID string) (Environment, error)
	// Update replaces the three settings of one environment. A missing id,
	// or one that belongs to another project, is ErrNotFound.
	Update(ctx context.Context, id, projectID, tier string, internetFacing bool, dataSensitivity string) (Environment, error)
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
	// Status is the review state: pending, approved, rejected or withdrawn.
	// Only approved waivers count in the gate.
	Status string
	// ScopeAll marks a waiver that covers every finding of the project. A
	// waiver without contexts, targets or conditions covers nothing unless
	// this is set.
	ScopeAll bool
	// ExpiresAt bounds an auto-disabled waiver; nil means it never expires.
	ExpiresAt *time.Time
	// Reason is the requester's justification. RequestedBy and RequestedAt
	// are nil for waivers created directly or before the review lifecycle.
	Reason      string
	RequestedBy *string
	RequestedAt *time.Time
	// DecidedBy, DecidedAt and DecisionNote record the review outcome.
	DecidedBy    *string
	DecidedAt    *time.Time
	DecisionNote string
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// WaiverCondition is one waiver predicate.
type WaiverCondition struct {
	ID       string
	WaiverID string
	Field    string
	Operator string
	Value    string
}

// WaiverContext is one waiver scope. Empty IDs are wildcards.
type WaiverContext struct {
	ID            string
	WaiverID      string
	EnvironmentID string
	TargetID      string
	ArtifactID    string
}

// WaiverFindingTarget pins a waiver to a finding.
type WaiverFindingTarget struct {
	ID        string
	WaiverID  string
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
// WaiverExpiry is the tri-state expiry input for waiver updates: At sets a
// new expiry, Clear writes NULL, and a nil *WaiverExpiry leaves the stored
// value untouched.
type WaiverExpiry struct {
	At    *time.Time
	Clear bool
}

type WaiverEventInput struct {
	EventType string
	ActorID   *string
	Metadata  json.RawMessage
}

// WaiverEnabledChange asks for a waiver to be switched on or off. Unlike a
// toggle it names the wanted state, so repeating it changes nothing.
type WaiverEnabledChange struct {
	Enabled bool
	// ExpectedUpdatedAt, when set, makes the change conditional on the
	// waiver still carrying that updated_at, to the microsecond.
	ExpectedUpdatedAt *time.Time
	// Event is appended in the same transaction, only when the state
	// actually changes.
	Event WaiverEventInput
}

// CreateWaiverInput carries a waiver and its children plus the audit event
// written in the same transaction.
type CreateWaiverInput struct {
	ProjectID   string
	Name        string
	Description string
	Enabled     bool
	// ExpiresAt optionally bounds the waiver; nil creates a permanent one.
	ExpiresAt *time.Time
	// Status is the initial review state; empty means approved.
	Status      string
	Reason      string
	RequestedBy *string
	RequestedAt *time.Time
	Conditions  []WaiverCondition
	Contexts    []WaiverContext
	Targets     []WaiverFindingTarget
	Event       WaiverEventInput
}

// WaiverDecision moves a pending waiver to a final status.
type WaiverDecision struct {
	// Status is the target: approved, rejected or withdrawn.
	Status string
	// ActorID is the user id of the decider.
	ActorID string
	// Note is the decision note (required for a rejection).
	Note  string
	Event WaiverEventInput
}

// WaiverStore persists waivers and their children/events atomically.
type WaiverStore interface {
	// Decide moves a pending waiver to a final status and appends the audit
	// event in one transaction. It returns ErrNotFound when the waiver does
	// not exist in the project and ErrWaiverNotPending when it already has
	// a final status.
	Decide(ctx context.Context, id, projectID string, decision WaiverDecision) (Waiver, error)
	CreateWithDetails(ctx context.Context, input CreateWaiverInput) (Waiver, error)
	List(ctx context.Context, projectID string) ([]Waiver, error)
	GetByID(ctx context.Context, id, projectID string) (Waiver, error)
	UpdateWithDetails(ctx context.Context, waiver Waiver, expiry *WaiverExpiry, conditions *[]WaiverCondition, contexts *[]WaiverContext, targets *[]WaiverFindingTarget, event WaiverEventInput) (Waiver, error)
	Delete(ctx context.Context, id, projectID string) error
	// ToggleWithEvent flips an approved waiver and records the event. It is
	// deprecated in favour of SetEnabled and returns ErrWaiverNotApproved or
	// ErrWaiverLapsed when the flip is refused.
	ToggleWithEvent(ctx context.Context, id, projectID, actorID string) (Waiver, error)
	// SetEnabled switches an approved waiver on or off. It returns the waiver
	// unchanged, and writes no event, when it already has the wanted state.
	// It returns ErrNotFound, ErrWaiverNotApproved, ErrWaiverChanged or
	// ErrWaiverLapsed when the change is refused.
	SetEnabled(ctx context.Context, id, projectID string, change WaiverEnabledChange) (Waiver, error)
	ListActive(ctx context.Context, projectID string) ([]Waiver, error)
	ListConditions(ctx context.Context, waiverID string) ([]WaiverCondition, error)
	ListConditionsByWaiverIDs(ctx context.Context, waiverIDs []string) ([]WaiverCondition, error)
	ListContexts(ctx context.Context, waiverID string) ([]WaiverContext, error)
	ListContextsByWaiverIDs(ctx context.Context, waiverIDs []string) ([]WaiverContext, error)
	ListFindingTargets(ctx context.Context, waiverID string) ([]WaiverFindingTarget, error)
	ListFindingTargetsByWaiverIDs(ctx context.Context, waiverIDs []string) ([]WaiverFindingTarget, error)
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
	// IntroducedByReportID is the report that first observed the finding;
	// nil means unattributed (e.g. watcher rows with no linked scan).
	// IntroducedCommitSha is the revision that report scanned. Attribution
	// is set at creation and refreshed only with improved evidence.
	IntroducedByReportID *string
	IntroducedCommitSha  *string
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
	// ExpectedState, when set, is a precondition: the write applies only
	// while the finding's analysis_state still equals it, otherwise the
	// store returns ErrAnalysisConflict.
	ExpectedState *string
}

// AnalysisUndoDecider decides an analysis undo while the finding is locked.
// current is the finding as it stands now and newest is its newest analysis
// event (nil when it has none). It returns the analysis write and the event
// to record, or an error that aborts the undo and rolls everything back.
type AnalysisUndoDecider func(current Finding, newest *FindingEvent) (UpdateAnalysisInput, FindingEventInput, error)

// UpsertFindingInput carries the fields of one finding upsert.
type UpsertFindingInput struct {
	ProjectID    string
	FindingKind  string
	Fingerprint  string
	Title        string
	Severity     string
	SeverityRank int16
	Score        float64
	FirstSeen    time.Time
	LastSeen     time.Time
}

// ListFindingsParams filters and pages the project finding list. Empty
// slices mean no filter.
type ListFindingsParams struct {
	Severities   []string
	States       []string
	Kinds        []string
	Environments []string
	Targets      []string
	// AnalysisStates filters on the analysis state; "unanalyzed" also
	// matches findings whose state was never written.
	AnalysisStates []string
	// Search is a LIKE pattern, already escaped, matched against the title
	// and the fingerprint. Empty means no text filter.
	Search string
	// SortKey is severity, first_seen, last_seen or title; SortDir is asc or
	// desc. Empty values give the default order: severity, most severe first.
	SortKey string
	SortDir string
	Limit   int32
	Offset  int32
}

// FindingStore persists findings, occurrences, dimensions, events, and the
// watcher finding unit-of-work.
type FindingStore interface {
	Upsert(ctx context.Context, input UpsertFindingInput) (Finding, error)
	GetByID(ctx context.Context, id string) (Finding, error)
	GetByFingerprint(ctx context.Context, projectID, findingKind, fingerprint string) (Finding, error)
	ListByIDs(ctx context.Context, ids []string) ([]Finding, error)
	ListByProject(ctx context.Context, projectID string, params ListFindingsParams) ([]Finding, error)
	// CountByProject counts the findings the same filters select, ignoring
	// the page window. It backs the list's X-Total-Count header.
	CountByProject(ctx context.Context, projectID string, params ListFindingsParams) (int64, error)
	UpdateAnalysis(ctx context.Context, input UpdateAnalysisInput) (Finding, error)
	// UpdateAnalysisWithEvent atomically updates analysis state and records
	// its audit event, returning the updated finding and the stored event.
	UpdateAnalysisWithEvent(ctx context.Context, input UpdateAnalysisInput, event FindingEventInput) (Finding, FindingEvent, error)
	// UndoAnalysis runs decide in one transaction that holds the finding's
	// row lock, then applies the analysis write and event it returns. Nothing
	// else can change the finding between the decision and the write.
	// ErrNotFound means the finding does not exist.
	UndoAnalysis(ctx context.Context, findingID string, decide AnalysisUndoDecider) (Finding, FindingEvent, error)
	BulkUpdateAnalysis(ctx context.Context, input UpdateAnalysisInput, ids []string) ([]Finding, error)
	BulkTriage(ctx context.Context, input UpdateAnalysisInput, ids []string, event FindingEventInput) ([]Finding, error)
	CreateEvent(ctx context.Context, input FindingEventInput) (FindingEvent, error)
	ListEvents(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]FindingEvent, error)
	// ListDimensions returns every persisted dimension of a finding,
	// ordered by key for determinism.
	ListDimensions(ctx context.Context, findingID string) ([]FindingDimension, error)
	// HasOccurrence reports whether a finding was observed in a report.
	HasOccurrence(ctx context.Context, findingID, reportID string) (bool, error)
	// MarkFixed moves a finding to the scan-derived fixed state. Triage
	// never sets it: VerifyFix is the analyst-facing path, backed by a
	// rescan that no longer observes the finding.
	MarkFixed(ctx context.Context, findingID string) (Finding, error)
	// MarkFixedWithEvent atomically marks a finding fixed and records its audit event.
	MarkFixedWithEvent(ctx context.Context, findingID string, event FindingEventInput) (Finding, error)
	// MarkAbsentFindingsFixed is the ingest-time auto-fix writer: it closes
	// open or reopened findings whose most recent observation came from an
	// equivalent complete scan (same project and scope hash) and that
	// reportID does not observe, returning the closed findings. Callers gate
	// it to full scans whose parsed
	// completeness is "complete".
	MarkAbsentFindingsFixed(ctx context.Context, projectID, scopeHash, reportID string) ([]Finding, error)
	// BulkCreateEvents records one event shape for many findings in a
	// single statement, keeping large closures (the auto-fix writer)
	// O(1) in queries instead of O(findings).
	BulkCreateEvents(ctx context.Context, findingIDs []string, input FindingEventInput) error
	// SetFindingIntroducedBy materializes introduced-by-change attribution.
	SetFindingIntroducedBy(ctx context.Context, findingID, reportID string, commitSha *string) (Finding, error)
	// ListIntroducedByReport returns findings one report introduced.
	ListIntroducedByReport(ctx context.Context, projectID, reportID string) ([]Finding, error)
	HasDimension(ctx context.Context, findingID, key string) (bool, error)
	CreateOccurrence(ctx context.Context, input OccurrenceInput) (Occurrence, error)
	UpsertDimension(ctx context.Context, input DimensionInput) error
	GetFindingContext(ctx context.Context, findingID string) (FindingContext, error)
	// GetFindingDisplayContext returns the latest observed deployment
	// context of a finding for detail views: target, environment, branch,
	// and commit names. Every field is empty when the context is missing —
	// missing context is explicit, never a placeholder string.
	GetFindingDisplayContext(ctx context.Context, findingID string) (FindingDisplayContext, error)
	ListFindingDisplayContextsByIDs(ctx context.Context, findingIDs []string) ([]FindingDisplayContext, error)
	ListBlockingFindings(ctx context.Context, projectID string, minSeverityRank int16) ([]Finding, error)
	// ListGateCandidates loads every gate candidate with its context and
	// latest reachability in one batch (kills the per-finding N+1 context
	// lookups). Reachability is empty when no assessment exists.
	ListGateCandidates(ctx context.Context, projectID string, minSeverityRank int16) ([]GateCandidate, error)
	// ListIntroducedGateCandidates returns the findings one report introduced,
	// filtered by the report's project so a foreign report id can never pull
	// another tenant's rows into a gate evaluation.
	ListIntroducedGateCandidates(ctx context.Context, projectID, reportID string, minSeverityRank int16) ([]GateCandidate, error)
	ListFindingsByFingerprints(ctx context.Context, projectID, findingKind string, fingerprints []string) ([]Finding, error)
	ListFindingIDsPresentInReport(ctx context.Context, reportID string, findingIDs []string) ([]string, error)
	RecordReportIntroducedFindings(ctx context.Context, reportID string, baselineReportID *string, entries []IntroducedFindingEntry) error
	ListFindingsIntroducedByCommit(ctx context.Context, projectID, commitSha string) ([]Finding, error)
	FindScaFindingIDForPurlAndCve(ctx context.Context, projectID, purlName string, candidateIDs []string) (string, error)

	// Watcher unit-of-work: insert the finding and its dependent rows
	// atomically. Returns ErrFindingSuppressed when the fingerprint already
	// exists (re-poll hit).
	PersistWatcherFinding(ctx context.Context, input PersistWatcherFindingInput) (Finding, error)
	// PersistWatcherSkipEvent appends an audit event to the suppressing
	// finding.
	PersistWatcherSkipEvent(ctx context.Context, findingID string, event FindingEventInput) error
}

// FindingIngestBatchStore is an optional bulk-write capability for report
// ingestion. Stores that implement it can persist independent occurrences and
// dimensions in set-based queries without changing the FindingStore contract.
type FindingIngestBatchStore interface {
	BulkCreateOccurrences(ctx context.Context, occurrences []OccurrenceInput) error
	BulkUpsertDimensions(ctx context.Context, source string, dimensions []DimensionInput) error
}

// IntroducedFindingEntry associates a finding with a report that introduced or regressed it.
type IntroducedFindingEntry struct {
	FindingID  string
	ChangeType string // "new" | "regression"
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
	FindingID       string
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

// ReportFilter narrows a report listing. Empty fields match every report.
type ReportFilter struct {
	// Branch is an exact branch name.
	Branch string
	// CommitSha is an exact commit id.
	CommitSha string
}

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
	// BaseRevision is the revision an incremental scan was compared against
	// (empty for full scans). ChangedFiles lists paths the scan covered.
	// ScanMode is "full" or "incremental" as requested at ingest.
	BaseRevision *string
	ChangedFiles json.RawMessage
	ScanMode     string
	// ErrorMessage is the sanitized reason a failed report failed. It is
	// never the raw store error.
	ErrorMessage *string
	CreatedAt    time.Time
	CompletedAt  *time.Time
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
	BaseRevision     *string
	ChangedFiles     json.RawMessage
	ScanMode         string
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
	ListByProject(ctx context.Context, projectID string, filter ReportFilter, limit, offset int32) ([]Report, error)
	UpdateStatus(ctx context.Context, id, projectID string, status string, totalFindings int32, errorMessage *string) (Report, error)
	// LatestCompletedByScanner returns the newest completed report from
	// one scanner, or ErrNotFound when the scanner never completed.
	LatestCompletedByScanner(ctx context.Context, projectID, scanner string) (CompletedReport, error)
	// GetCompletedByCommit resolves the incremental-analysis baseline: the
	// newest completed same-scanner report for an exact revision, or
	// ErrNotFound when no baseline exists (caller falls back to full).
	GetCompletedByCommit(ctx context.Context, projectID, scanner, commit string) (CompletedReport, error)
	// HasCompletedForCommit reports whether any scanner completed a scan of the
	// exact revision. A PR check refuses to pass without such a scan.
	HasCompletedForCommit(ctx context.Context, projectID, commit string) (bool, error)

	// GetLatestFullByBranch returns the newest completed full report from
	// one scanner on a branch, or ErrNotFound. It is the baseline fallback
	// when base_revision names a branch instead of a commit.
	GetLatestFullByBranch(ctx context.Context, projectID, scanner, branch string) (CompletedReport, error)
	// LatestCompletedInFindingScope returns the newest completed full report
	// that shares the scan scope of the report that most recently observed
	// findingID, or ErrNotFound when no such report exists. Completeness is
	// left to the caller.
	LatestCompletedInFindingScope(ctx context.Context, projectID, findingID string) (CompletedReport, error)
	// CountStaleReports counts settled (completed/failed) reports older
	// than the cutoff. Processing reports are never counted.
	CountStaleReports(ctx context.Context, cutoff time.Time) (int64, error)
	// FailStale settles reports still processing since before the cutoff as
	// failed, with the reason as their error message, and returns how many it
	// changed. It is the recovery for an ingest the server stopped under.
	FailStale(ctx context.Context, cutoff time.Time, reason string) (int64, error)
	// DeleteStaleReports deletes settled reports older than the cutoff,
	// returning their ids. Each goes through DeleteReportAndSettle, so a
	// retention purge and an explicit delete leave the same state behind.
	DeleteStaleReports(ctx context.Context, cutoff time.Time) ([]string, error)
	// DeleteReportAndSettle deletes one report in a transaction and settles
	// the findings it was evidence for: open findings with no occurrence left
	// become archived (with a report_deleted event naming actorID, nil for the
	// system), and findings the report introduced are attributed to the
	// earliest report that still shows them. Returns ErrNotFound for a report
	// that is not in the project and ErrReportProcessing while a scan is
	// writing it.
	DeleteReportAndSettle(ctx context.Context, id, projectID string, actorID *string) (ReportDeletion, error)
	// FindCompletedByReplayKey returns a completed report's id for identical
	// raw content at the same commit and scan scope, or ErrNotFound. The replay
	// guard: a NULL commit_sha or scan_scope_hash and an empty one compare
	// equal.
	FindCompletedByReplayKey(ctx context.Context, projectID, rawHash, commit, scopeHash string) (string, error)
	// DeleteReport removes one report row (duplicate-cleanup path).
	DeleteReport(ctx context.Context, id, projectID string) error
	// DeleteDuplicateReport removes a race loser's processing row and moves the
	// finding attribution it introduced to the winning report in one
	// transaction, so deleting the loser cannot null that attribution.
	DeleteDuplicateReport(ctx context.Context, id, projectID, winnerID string) error
}

// CompletedReport is the verification basis: the newest completed scan
// from one scanner with its revision and scope completeness.
type CompletedReport struct {
	ID           string
	ToolName     string
	Branch       *string
	CommitSha    *string
	BaseRevision *string
	ScanMode     string
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
	Severity string
	// Rank is the severity's rank, which the gate's per-rank blocking counts
	// are keyed by.
	Rank  int16
	Count int32
}

// WeeklyCount is the number of findings first seen in one week.
type WeeklyCount struct {
	// WeekStart is the Monday of the week, as 2006-01-02 (UTC).
	WeekStart string
	Count     int32
}

// ReportDeletion reports what deleting a report changed.
type ReportDeletion struct {
	// ArchivedFindings is the number of findings archived because the report
	// was their only evidence.
	ArchivedFindings int
}

// MaxAgingRows caps the open findings the aging report evaluates.
const MaxAgingRows = 10000

// AnalysisStateStat is one analysis-state bucket of project stats.
type AnalysisStateStat struct {
	State string
	Count int32
}

// StatsStore serves aggregate project statistics.
type StatsStore interface {
	GetProjectStats(ctx context.Context, projectID string) ([]SeverityStat, error)
	GetProjectAnalysisStateCounts(ctx context.Context, projectID string) ([]AnalysisStateStat, error)
	GetProjectWaiverCount(ctx context.Context, projectID string) (int32, error)
	GetProjectPendingWaiverCount(ctx context.Context, projectID string) (int32, error)
	GetProjectReportCount(ctx context.Context, projectID string) (int32, error)
	GetProjectLatestReport(ctx context.Context, projectID string) (Report, error)
	// GetAgingRows loads the aging input of a project's open findings, oldest
	// first, up to MaxAgingRows. truncated is true when the project has more.
	GetAgingRows(ctx context.Context, projectID string) (rows []AgingRow, truncated bool, err error)
	// GetNewFindingCounts counts the findings first seen since a time, per
	// week, whatever state they are in now.
	GetNewFindingCounts(ctx context.Context, projectID string, since time.Time) ([]WeeklyCount, error)
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
	// UpdateProjectConfig sets the per-project watcher switch and interval; a
	// nil argument leaves that setting unchanged. It returns ErrNotFound for
	// an unknown project.
	UpdateProjectConfig(ctx context.Context, projectID string, enabled *bool, intervalSeconds *int32) (Project, error)
	GetProjectState(ctx context.Context, projectID string) (WatcherProjectState, error)
	UpsertProjectState(ctx context.Context, projectID string, ts time.Time) error
}

// ---------- Aggregate ----------

// Stores is the aggregate persistence handle the core depends on. It is the
// port counterpart of repo.Repos.
type Stores struct {
	Projects        ProjectStore
	Users           UserStore
	RefreshTokens   RefreshTokenStore
	APIKeys         APIKeyStore
	Environments    EnvironmentStore
	Targets         TargetStore
	Artifacts       ArtifactStore
	Waivers         WaiverStore
	Findings        FindingStore
	Evidence        EvidenceStore
	Reachability    ReachabilityStore
	Signoffs        SignoffStore
	Reports         ReportStore
	Inventory       InventoryStore
	Stats           StatsStore
	Watcher         WatcherStore
	Admin           AdminStore
	Policy          PolicyStore
	Teams           TeamStore
	Identities      IdentityStore
	SSOCodes        SSOCodeStore
	Invites         InviteStore
	PasswordReset   PasswordResetStore
	InstanceSecrets InstanceSecretStore
}

// Team is a named group of users that projects link for access.
type Team struct {
	ID          string
	Name        string
	Description string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// TeamMember binds a user to a team as admin (manages the team) or member.
type TeamMember struct {
	TeamID      string
	UserID      string
	UserEmail   string
	DisplayName string
	Role        string
	CreatedAt   time.Time
}

// ProjectTeam links a team to a project, conferring the link role on
// every team member.
type ProjectTeam struct {
	ProjectID string
	TeamID    string
	TeamName  string
	Role      string
	CreatedAt time.Time
}

// TeamStore persists teams, their memberships, and project links.
type TeamStore interface {
	CreateTeam(ctx context.Context, name, description string) (Team, error)
	GetTeamByID(ctx context.Context, id string) (Team, error)
	GetTeamByName(ctx context.Context, name string) (Team, error)
	ListTeams(ctx context.Context) ([]Team, error)
	DeleteTeam(ctx context.Context, id string) error
	UpsertTeamMember(ctx context.Context, teamID, userID, role string) (TeamMember, error)
	ListTeamMembers(ctx context.Context, teamID string) ([]TeamMember, error)
	RemoveTeamMember(ctx context.Context, teamID, userID string) error
	IsTeamMember(ctx context.Context, teamID, userID string) (bool, error)
	IsTeamAdmin(ctx context.Context, teamID, userID string) (bool, error)
	LinkProjectTeam(ctx context.Context, projectID, teamID, role string) (ProjectTeam, error)
	UnlinkProjectTeam(ctx context.Context, projectID, teamID string) error
	ListProjectTeams(ctx context.Context, projectID string) ([]ProjectTeam, error)
	// ListTeamProjectLinks returns every project a team is linked to,
	// with the role each link confers on the team's members.
	ListTeamProjectLinks(ctx context.Context, teamID string) ([]ProjectTeam, error)
}

// PolicyTemplate is a reusable organization-wide policy baseline.
type PolicyTemplate struct {
	ID          string
	Name        string
	Description string
	Definition  json.RawMessage
	Version     int32
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// PolicyTemplateInput carries template create/update fields.
type PolicyTemplateInput struct {
	Name        string
	Description string
	Definition  json.RawMessage
}

// PolicyStore persists policy templates and project assignments.
type PolicyStore interface {
	CreateTemplate(ctx context.Context, input PolicyTemplateInput) (PolicyTemplate, error)
	GetTemplateByID(ctx context.Context, id string) (PolicyTemplate, error)
	GetTemplateByName(ctx context.Context, name string) (PolicyTemplate, error)
	ListTemplates(ctx context.Context) ([]PolicyTemplate, error)
	UpdateTemplate(ctx context.Context, id string, input PolicyTemplateInput) (PolicyTemplate, error)
	DeleteTemplate(ctx context.Context, id string) error
	SetProjectTemplate(ctx context.Context, projectID string, templateID *string) (Project, error)
}

// AdminOverview is one row of platform-wide counts for the admin status
// surface.
type AdminOverview struct {
	ProjectCount          int64
	UserCount             int64
	OpenFindingCount      int64
	ReportCount           int64
	OldestSettledReportAt *time.Time
}

// AdminStore serves platform observability aggregates.
type AdminStore interface {
	Overview(ctx context.Context) (AdminOverview, error)
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

// Invite is a single-use link that brings a person into one project.
type Invite struct {
	ID             string
	ProjectID      string
	Role           string
	Email          *string
	CreatedBy      *string
	CreatedByEmail *string
	CreatedAt      time.Time
	ExpiresAt      time.Time
}

// NewInvite is the data to store for a new invite. TokenHash is the SHA-256 of
// the link's token; the token itself is never stored.
type NewInvite struct {
	TokenHash string
	ProjectID string
	Role      string
	Email     *string
	CreatedBy string
	ExpiresAt time.Time
}

// InviteView is what the accept page may show to whoever holds the link.
type InviteView struct {
	ProjectName string
	Role        string
	Email       *string
}

// InviteeAccount is the account an invite creates when the person has none.
type InviteeAccount struct {
	Email        string
	DisplayName  *string
	PasswordHash string
}

// AcceptedInvite reports what accepting an invite did.
type AcceptedInvite struct {
	User        User
	ProjectID   string
	ProjectSlug string
	// Role is the project role the person holds now; a stronger role they
	// already had is kept.
	Role     string
	InviteID string
}

// InviteStore persists invite links. Pending means not used, not revoked and
// not expired.
type InviteStore interface {
	Create(ctx context.Context, in NewInvite) (Invite, error)
	CountPending(ctx context.Context, projectID string) (int64, error)
	ListPending(ctx context.Context, projectID string) ([]Invite, error)
	// GetPending and Revoke return ErrNotFound for an invite that is not pending.
	GetPending(ctx context.Context, projectID, id string) (Invite, error)
	Revoke(ctx context.Context, projectID, id string) (Invite, error)
	// Lookup returns ErrNotFound for a token that is unknown, used, revoked or expired.
	Lookup(ctx context.Context, tokenHash string) (InviteView, error)
	// AcceptWithNewAccount marks the invite used, creates the account and adds
	// it to the project in one transaction. Errors: ErrNotFound (not pending),
	// ErrInviteEmailMismatch, ErrEmailTaken. A failure leaves the invite pending.
	AcceptWithNewAccount(ctx context.Context, tokenHash string, account InviteeAccount) (AcceptedInvite, error)
	// AcceptAsUser does the same for an existing account.
	AcceptAsUser(ctx context.Context, tokenHash, userID string) (AcceptedInvite, error)
}

// NewPasswordReset is the data to store for a reset link. TokenHash is the
// SHA-256 of the token; the token itself is never stored.
type NewPasswordReset struct {
	TokenHash string
	UserID    string
	CreatedBy string
	ExpiresAt time.Time
}

// PasswordResetStore persists password reset links.
type PasswordResetStore interface {
	// Create stores a link and retires every earlier unused link for the same
	// account, in one transaction.
	Create(ctx context.Context, in NewPasswordReset) error
	// Redeem marks the link used, ends every session of its account and sets the
	// new password hash, in one transaction. It returns the account id. A link
	// that is unknown, used, retired or expired returns ErrNotFound and changes
	// nothing.
	Redeem(ctx context.Context, tokenHash, passwordHash string) (string, error)
}

// InstanceSecretStore keeps values that belong to one installation, such as the
// key finding identities for secrets are hashed with.
type InstanceSecretStore interface {
	// Ensure stores value under name when the name is new and returns whatever
	// is stored. Callers racing on first use all receive the same value.
	Ensure(ctx context.Context, name string, value []byte) ([]byte, error)
}
