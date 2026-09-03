// Package repo implements the persistence seam between use cases and the
// sqlc-generated query layer. Repositories own row-level CRUD and the
// multi-table unit-of-work transactions (waiver create/update, watcher
// finding persistence); use cases never execute SQL directly.
package repo

import (
	"context"
	"fmt"

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

type ProjectRepo interface {
	Create(ctx context.Context, arg sqlc.CreateProjectParams) (sqlc.Project, error)
	List(ctx context.Context) ([]sqlc.Project, error)
	GetBySlug(ctx context.Context, slug string) (sqlc.Project, error)
}

type ReportRepo interface {
	Create(ctx context.Context, arg CreateReportParams) (sqlc.Report, error)
	GetByID(ctx context.Context, id pgtype.UUID) (sqlc.Report, error)
	ListByProject(ctx context.Context, projectID pgtype.UUID, limit, offset int32) ([]sqlc.Report, error)
	UpdateStatus(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error)
}

type UserRepo interface {
	Create(ctx context.Context, email string, displayName, passwordHash pgtype.Text) (sqlc.User, error)
	GetByEmail(ctx context.Context, email string) (sqlc.User, error)
	GetByID(ctx context.Context, id pgtype.UUID) (sqlc.User, error)
}

type APIKeyRepo interface {
	Create(ctx context.Context, arg sqlc.CreateAPIKeyParams) (sqlc.ApiKey, error)
	ListByProject(ctx context.Context, projectID pgtype.UUID) ([]sqlc.ListAPIKeysByProjectRow, error)
	GetByHash(ctx context.Context, keyHash string) (sqlc.ApiKey, error)
	Revoke(ctx context.Context, id, projectID pgtype.UUID) (sqlc.ApiKey, error)
}

type EnvironmentRepo interface {
	Upsert(ctx context.Context, arg sqlc.UpsertEnvironmentParams) (sqlc.Environment, error)
	List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Environment, error)
	GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Environment, error)
	Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Environment, error)
}

type TargetRepo interface {
	Upsert(ctx context.Context, arg sqlc.UpsertTargetParams) (sqlc.Target, error)
	List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Target, error)
	GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Target, error)
	Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Target, error)
}

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
	CreateCondition(ctx context.Context, arg sqlc.CreateWaiverConditionParams) (sqlc.WaiverCondition, error)
	DeleteConditions(ctx context.Context, waiverID pgtype.UUID) error
	ListContexts(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverContext, error)
	CreateContext(ctx context.Context, arg sqlc.CreateWaiverContextParams) (sqlc.WaiverContext, error)
	DeleteContexts(ctx context.Context, waiverID pgtype.UUID) error
	ListFindingTargets(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverFindingTarget, error)
	CreateFindingTarget(ctx context.Context, arg sqlc.CreateWaiverFindingTargetParams) (sqlc.WaiverFindingTarget, error)
	DeleteFindingTargets(ctx context.Context, waiverID pgtype.UUID) error
	CreateEvent(ctx context.Context, arg sqlc.CreateWaiverEventParams) (sqlc.WaiverEvent, error)
	ListEvents(ctx context.Context, waiverID pgtype.UUID) ([]sqlc.WaiverEvent, error)
}

type ArtifactRepo interface {
	Upsert(ctx context.Context, arg sqlc.UpsertArtifactParams) (sqlc.Artifact, error)
	List(ctx context.Context, projectID pgtype.UUID) ([]sqlc.Artifact, error)
	ListByTarget(ctx context.Context, targetID pgtype.UUID) ([]sqlc.Artifact, error)
	GetByID(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Artifact, error)
	Delete(ctx context.Context, id, projectID pgtype.UUID) (sqlc.Artifact, error)
}

type SignoffRepo interface {
	Upsert(ctx context.Context, arg UpsertSignoffParams) (sqlc.Signoff, error)
	GetByFinding(ctx context.Context, findingID pgtype.UUID) (sqlc.Signoff, error)
}

type InventoryRepo interface {
	UpsertReportPackages(ctx context.Context, reportID pgtype.UUID, packages []UpsertReportPackageParams) error
	DistinctInventory(ctx context.Context, projectID pgtype.UUID, since pgtype.Interval) ([]sqlc.DistinctInventoryRow, error)
	DeleteReportPackages(ctx context.Context, reportID pgtype.UUID) error
}

type ReachabilityRepo interface {
	Upsert(ctx context.Context, arg UpsertReachabilityParams) (sqlc.ReachabilityAssessment, error)
	ListByFinding(ctx context.Context, findingID pgtype.UUID) ([]sqlc.ReachabilityAssessment, error)
	GetByID(ctx context.Context, id pgtype.UUID) (sqlc.ReachabilityAssessment, error)
}

type EvidenceRepo interface {
	Create(ctx context.Context, arg CreateEvidenceParams) (sqlc.EvidenceArtifact, error)
	ListByFinding(ctx context.Context, findingID pgtype.UUID) ([]sqlc.EvidenceArtifact, error)
	GetByID(ctx context.Context, id pgtype.UUID) (sqlc.EvidenceArtifact, error)
	Delete(ctx context.Context, id pgtype.UUID) error
}

type FindingRepo interface {
	Upsert(ctx context.Context, arg UpsertFindingParams) (sqlc.Finding, error)
	PersistWatcherFinding(ctx context.Context, arg PersistWatcherFindingParams) (sqlc.Finding, bool, error)
	PersistWatcherSkipEvent(ctx context.Context, arg sqlc.CreateFindingEventParams) error
	CreateOccurrence(ctx context.Context, arg CreateOccurrenceParams) (sqlc.FindingOccurrence, error)
	UpsertDimension(ctx context.Context, arg UpsertDimensionParams) (sqlc.FindingDimension, error)
	ListByProject(ctx context.Context, projectID pgtype.UUID, severities, states, kinds []string, limit, offset int32) ([]sqlc.Finding, error)
	GetByID(ctx context.Context, id pgtype.UUID) (sqlc.Finding, error)
	GetByFingerprint(ctx context.Context, arg GetByFingerprintParams) (sqlc.Finding, error)
	ListByIDs(ctx context.Context, ids []pgtype.UUID) ([]sqlc.Finding, error)
	UpdateAnalysis(ctx context.Context, arg UpdateAnalysisParams) (sqlc.Finding, error)
	BulkUpdateAnalysis(ctx context.Context, arg BulkUpdateAnalysisParams) ([]sqlc.Finding, error)
	GateEval(ctx context.Context, arg GateEvalParams) (bool, error)
	CountBlocking(ctx context.Context, arg GateEvalParams) (int64, error)
	ListBlockingFindings(ctx context.Context, projectID pgtype.UUID, minSeverityRank int16) ([]sqlc.Finding, error)
	CreateEvent(ctx context.Context, arg CreateEventParams) (sqlc.FindingEvent, error)
	ListEvents(ctx context.Context, findingID pgtype.UUID, eventTypes []string, limit, offset int32) ([]sqlc.FindingEvent, error)
	HasDimension(ctx context.Context, findingID pgtype.UUID, key string) (bool, error)
	GetFindingContext(ctx context.Context, findingID pgtype.UUID) (FindingContext, error)
	FindScaFindingIdForPurlAndCve(ctx context.Context, projectID pgtype.UUID, purlName string, candidateIDs []string) (pgtype.UUID, error)
}
