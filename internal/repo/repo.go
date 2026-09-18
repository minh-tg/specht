// Package repo implements the PostgreSQL adapter for the neutral persistence
// contracts in internal/port. Repositories own row-level CRUD over the
// sqlc-generated query layer and the multi-table unit-of-work transactions
// (waiver create/update, watcher finding persistence, expiry sweeps); use
// cases, lifecycle, and watcher depend only on the port interfaces, never on
// sqlc/pgtype types.
package repo

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

// Repos is the aggregate persistence handle: one field per domain repository,
// backed by a shared pgx pool. It is the single repo value wired into use
// cases and commands.
type Repos struct {
	Projects      ProjectRepo
	Reports       ReportRepo
	Findings      FindingRepo
	Users         UserRepo
	APIKeys       APIKeyRepo
	RefreshTokens RefreshTokenRepo
	Environments  EnvironmentRepo
	Targets       TargetRepo
	Artifacts     ArtifactRepo
	Waivers       WaiverRepo
	Stats         StatsRepo
	Evidence      EvidenceRepo
	Reachability  ReachabilityRepo
	Signoffs      SignoffRepo
	Inventory     InventoryRepo
	Watcher       WatcherRepo
	pool          *pgxpool.Pool
}

// NewRepos builds every repository over a single pgx pool.
func NewRepos(pool *pgxpool.Pool) *Repos {
	q := sqlc.New(pool)
	return &Repos{
		Projects:      &pgProjectRepo{q: q},
		Reports:       &pgReportRepo{q: q},
		Findings:      &pgFindingRepo{q: q, pool: pool},
		Users:         &pgUserRepo{q: q},
		APIKeys:       &pgAPIKeyRepo{q: q},
		RefreshTokens: &pgRefreshTokenRepo{q: q},
		Environments:  &pgEnvironmentRepo{q: q},
		Targets:       &pgTargetRepo{q: q},
		Artifacts:     &pgArtifactRepo{q: q},
		Waivers:       &pgWaiverRepo{q: q, pool: pool},
		Stats:         newStatsRepo(q),
		Evidence:      newEvidenceRepo(q),
		Reachability:  newReachabilityRepo(q),
		Signoffs:      newSignoffRepo(q),
		Inventory:     &pgInventoryRepo{query: q, pool: pool},
		Watcher:       newWatcherRepo(q),
		pool:          pool,
	}
}

// WithTx executes fn within a database transaction.
func (r *Repos) WithTx(ctx context.Context, fn func(q *sqlc.Queries) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	q := sqlc.New(tx)
	if err := fn(q); err != nil {
		return err
	}

	return tx.Commit(ctx)
}

// ProjectRepo persists scan projects.
type ProjectRepo interface {
	Create(ctx context.Context, arg sqlc.CreateProjectParams) (sqlc.Project, error)
	List(ctx context.Context) ([]sqlc.Project, error)
	GetBySlug(ctx context.Context, slug string) (sqlc.Project, error)
}

// ReportRepo persists ingested scan reports.
type ReportRepo interface {
	Create(ctx context.Context, arg CreateReportParams) (sqlc.Report, error)
	GetByID(ctx context.Context, id pgtype.UUID) (sqlc.Report, error)
	ListByProject(ctx context.Context, projectID pgtype.UUID, limit, offset int32) ([]sqlc.Report, error)
	UpdateStatus(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error)
	LatestCompletedByScanner(ctx context.Context, projectID pgtype.UUID, toolName string) (sqlc.LatestCompletedReportByScannerRow, error)
	GetCompletedByCommit(ctx context.Context, projectID pgtype.UUID, toolName string, commit pgtype.Text) (sqlc.GetCompletedReportByCommitRow, error)
	CountStaleReports(ctx context.Context, cutoff time.Time) (int64, error)
	DeleteStaleReports(ctx context.Context, cutoff time.Time) ([]pgtype.UUID, error)
	FindCompletedByHash(ctx context.Context, projectID pgtype.UUID, rawHash pgtype.Text) (pgtype.UUID, error)
	DeleteReport(ctx context.Context, id, projectID pgtype.UUID) error
}

// UserRepo persists user accounts.
type UserRepo interface {
	Create(ctx context.Context, email string, displayName, passwordHash pgtype.Text) (sqlc.User, error)
	GetByEmail(ctx context.Context, email string) (sqlc.User, error)
	GetByID(ctx context.Context, id pgtype.UUID) (sqlc.User, error)
}

// APIKeyRepo persists project-scoped API keys.
type APIKeyRepo interface {
	Create(ctx context.Context, arg sqlc.CreateAPIKeyParams) (sqlc.ApiKey, error)
	ListByProject(ctx context.Context, projectID pgtype.UUID) ([]sqlc.ListAPIKeysByProjectRow, error)
	GetByHash(ctx context.Context, keyHash string) (sqlc.ApiKey, error)
	Revoke(ctx context.Context, id, projectID pgtype.UUID) (sqlc.ApiKey, error)
	TouchLastUsed(ctx context.Context, id pgtype.UUID) error
}

// EnvironmentRepo persists deployment environments.
type EnvironmentRepo interface {
	Upsert(ctx context.Context, arg sqlc.UpsertEnvironmentParams) (sqlc.Environment, error)
	List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Environment, error)
	GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Environment, error)
	Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Environment, error)
}

// TargetRepo persists scan targets.
type TargetRepo interface {
	Upsert(ctx context.Context, arg sqlc.UpsertTargetParams) (sqlc.Target, error)
	List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Target, error)
	GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Target, error)
	Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Target, error)
}

// WaiverRepo persists waiver policies and their conditions, contexts, targets, and events.
type WaiverRepo interface {
	Create(ctx context.Context, arg sqlc.CreateWaiverParams) (sqlc.Waiver, error)
	CreateWithDetails(ctx context.Context, arg CreateWaiverDetailsParams) (sqlc.Waiver, error)
	List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Waiver, error)
	GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Waiver, error)
	Update(ctx context.Context, arg sqlc.UpdateWaiverParams) (sqlc.Waiver, error)
	UpdateWithDetails(ctx context.Context, arg UpdateWaiverDetailsParams) (sqlc.Waiver, error)
	Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Waiver, error)
	Toggle(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Waiver, error)
	ListActive(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Waiver, error)
	ListConditions(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverCondition, error)
	ListConditionsByWaiverIDs(ctx context.Context, waiverIDs []pgtype.UUID) ([]sqlc.WaiverCondition, error)
	CreateCondition(ctx context.Context, arg sqlc.CreateWaiverConditionParams) (sqlc.WaiverCondition, error)
	DeleteConditions(ctx context.Context, waiverID pgtype.UUID) error
	ListContexts(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverContext, error)
	ListContextsByWaiverIDs(ctx context.Context, waiverIDs []pgtype.UUID) ([]sqlc.WaiverContext, error)
	CreateContext(ctx context.Context, arg sqlc.CreateWaiverContextParams) (sqlc.WaiverContext, error)
	DeleteContexts(ctx context.Context, waiverID pgtype.UUID) error
	ListFindingTargets(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverFindingTarget, error)
	ListFindingTargetsByWaiverIDs(ctx context.Context, waiverIDs []pgtype.UUID) ([]sqlc.WaiverFindingTarget, error)
	CreateFindingTarget(ctx context.Context, arg sqlc.CreateWaiverFindingTargetParams) (sqlc.WaiverFindingTarget, error)
	DeleteFindingTargets(ctx context.Context, waiverID pgtype.UUID) error
	CreateEvent(ctx context.Context, arg sqlc.CreateWaiverEventParams) (sqlc.WaiverEvent, error)
	ListEvents(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverEvent, error)
}

// ArtifactRepo persists artifacts of scan targets.
type ArtifactRepo interface {
	Upsert(ctx context.Context, arg sqlc.UpsertArtifactParams) (sqlc.Artifact, error)
	List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Artifact, error)
	ListByTarget(ctx context.Context, targetID pgtype.UUID) ([]sqlc.Artifact, error)
	GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Artifact, error)
	Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Artifact, error)
}

// SignoffRepo persists finding signoffs.
type SignoffRepo interface {
	Upsert(ctx context.Context, arg UpsertSignoffParams) (sqlc.Signoff, error)
	GetByFinding(ctx context.Context, findingID pgtype.UUID) (sqlc.Signoff, error)
}

// InventoryRepo persists a report's package inventory and serves the watcher's distinct-package view.
type InventoryRepo interface {
	UpsertReportPackages(ctx context.Context, reportID pgtype.UUID, packages []UpsertReportPackageParams) error
	DistinctInventory(ctx context.Context, projectID pgtype.UUID, since pgtype.Interval) ([]sqlc.DistinctInventoryRow, error)
	DeleteReportPackages(ctx context.Context, reportID pgtype.UUID) error
}

// ReachabilityRepo persists reachability assessments.
type ReachabilityRepo interface {
	Upsert(ctx context.Context, arg UpsertReachabilityParams) (sqlc.ReachabilityAssessment, error)
	ListByFinding(ctx context.Context, findingID pgtype.UUID) ([]sqlc.ReachabilityAssessment, error)
	GetByID(ctx context.Context, id pgtype.UUID) (sqlc.ReachabilityAssessment, error)
	LatestByFinding(ctx context.Context, findingID pgtype.UUID) (sqlc.ReachabilityAssessment, error)
	LatestByFindings(ctx context.Context, findingIDs []pgtype.UUID) ([]sqlc.ReachabilityAssessment, error)
}

// EvidenceRepo persists evidence artifacts attached to findings.
type EvidenceRepo interface {
	Create(ctx context.Context, arg CreateEvidenceParams) (sqlc.EvidenceArtifact, error)
	ListByFinding(ctx context.Context, findingID pgtype.UUID) ([]sqlc.EvidenceArtifact, error)
	GetByID(ctx context.Context, id pgtype.UUID) (sqlc.EvidenceArtifact, error)
	Delete(ctx context.Context, id pgtype.UUID) error
}

// FindingRepo persists findings, occurrences, dimensions, events, and the watcher finding unit-of-work.
type FindingRepo interface {
	Upsert(ctx context.Context, arg UpsertFindingParams) (sqlc.Finding, error)
	PersistWatcherFinding(ctx context.Context, arg PersistWatcherFindingParams) (sqlc.Finding, bool, error)
	PersistWatcherSkipEvent(ctx context.Context, arg sqlc.CreateFindingEventParams) error
	CreateOccurrence(ctx context.Context, arg CreateOccurrenceParams) (sqlc.FindingOccurrence, error)
	UpsertDimension(ctx context.Context, arg UpsertDimensionParams) (sqlc.FindingDimension, error)
	ListDimensions(ctx context.Context, findingID pgtype.UUID) ([]sqlc.ListFindingDimensionsRow, error)
	ListByProject(ctx context.Context, projectID pgtype.UUID, severities, states, kinds, environments, targets []string, limit, offset int32) ([]sqlc.Finding, error)
	GetByID(ctx context.Context, id pgtype.UUID) (sqlc.Finding, error)
	GetByFingerprint(ctx context.Context, arg GetByFingerprintParams) (sqlc.Finding, error)
	ListByIDs(ctx context.Context, ids []pgtype.UUID) ([]sqlc.Finding, error)
	UpdateAnalysis(ctx context.Context, arg UpdateAnalysisParams) (sqlc.Finding, error)
	BulkUpdateAnalysis(ctx context.Context, arg BulkUpdateAnalysisParams) ([]sqlc.Finding, error)
	BulkTriage(ctx context.Context, arg BulkUpdateAnalysisParams, event CreateEventParams) ([]sqlc.Finding, error)
	ListBlockingFindings(ctx context.Context, projectID pgtype.UUID, minSeverityRank int16) ([]sqlc.Finding, error)
	// ListGateCandidates loads every gate candidate with its context and
	// latest reachability in one batch (the port batch method).
	ListGateCandidates(ctx context.Context, projectID pgtype.UUID, minSeverityRank int16) ([]sqlc.ListGateCandidatesRow, error)
	ListIntroducedGateCandidates(ctx context.Context, reportID pgtype.UUID, minSeverityRank int16) ([]sqlc.ListIntroducedGateCandidatesRow, error)
	ListFindingsByFingerprints(ctx context.Context, projectID pgtype.UUID, findingKind string, fingerprints []string) ([]sqlc.Finding, error)
	ListFindingIDsPresentInReport(ctx context.Context, reportID pgtype.UUID, findingIDs []pgtype.UUID) ([]pgtype.UUID, error)
	RecordReportIntroducedFindings(ctx context.Context, reportID pgtype.UUID, baselineReportID pgtype.UUID, findingIDs []pgtype.UUID, changeTypes []string) error
	ListFindingsIntroducedByCommit(ctx context.Context, projectID pgtype.UUID, commit pgtype.Text) ([]sqlc.Finding, error)
	CreateEvent(ctx context.Context, arg CreateEventParams) (sqlc.FindingEvent, error)
	ListEvents(ctx context.Context, findingID pgtype.UUID, eventTypes []string, limit, offset int32) ([]sqlc.FindingEvent, error)
	GetFindingContext(ctx context.Context, findingID pgtype.UUID) (FindingContext, error)
	GetFindingDisplayContext(ctx context.Context, findingID pgtype.UUID) (sqlc.GetFindingDisplayContextRow, error)
	ListFindingDisplayContextsByIDs(ctx context.Context, findingIDs []pgtype.UUID) ([]sqlc.ListFindingDisplayContextsByIDsRow, error)
	HasOccurrence(ctx context.Context, findingID, reportID pgtype.UUID) (bool, error)
	MarkFixed(ctx context.Context, findingID pgtype.UUID) (sqlc.Finding, error)
	SetIntroducedBy(ctx context.Context, findingID, reportID pgtype.UUID, commit pgtype.Text) (sqlc.Finding, error)
	ListIntroducedByReport(ctx context.Context, projectID, reportID pgtype.UUID) ([]sqlc.Finding, error)
	FindScaFindingIdForPurlAndCve(ctx context.Context, projectID pgtype.UUID, purlName string, candidateIDs []string) (pgtype.UUID, error)
}
