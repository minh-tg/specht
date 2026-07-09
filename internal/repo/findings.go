package repo

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

type pgFindingRepo struct {
	q *sqlc.Queries
}

func newFindingRepo(q *sqlc.Queries) *pgFindingRepo {
	return &pgFindingRepo{q: q}
}

type UpsertFindingParams struct {
	ProjectID    pgtype.UUID
	FindingKind  string
	Fingerprint  string
	CurrentTitle string
	Severity     string
	SeverityRank int16
	Score        pgtype.Numeric
	FirstSeenAt  pgtype.Timestamptz
	LastSeenAt   pgtype.Timestamptz
}

func (r *pgFindingRepo) ListByProject(ctx context.Context, projectID pgtype.UUID, severities, states []string, limit, offset int32) ([]sqlc.Finding, error) {
	return r.q.ListFindingsByProject(ctx, sqlc.ListFindingsByProjectParams{
		ProjectID: projectID,
		Column2:   severities,
		Column3:   states,
		Limit:     limit,
		Offset:    offset,
	})
}

func (r *pgFindingRepo) Upsert(ctx context.Context, arg UpsertFindingParams) (sqlc.Finding, error) {
	return r.q.UpsertFinding(ctx, sqlc.UpsertFindingParams{
		ProjectID:           arg.ProjectID,
		FindingKind:         arg.FindingKind,
		Fingerprint:         arg.Fingerprint,
		CurrentTitle:        arg.CurrentTitle,
		CurrentSeverity:     arg.Severity,
		CurrentSeverityRank: arg.SeverityRank,
		CurrentScore:        arg.Score,
		State:               "open",
		TriageStatus:        "untriaged",
		FirstSeenAt:         arg.FirstSeenAt,
		LastSeenAt:          arg.LastSeenAt,
	})
}

type CreateOccurrenceParams struct {
	FindingID       pgtype.UUID
	ReportID        pgtype.UUID
	Title           string
	Description     pgtype.Text
	Severity        string
	SeverityRank    int16
	Score           pgtype.Numeric
	ToolName        string
	ToolVersion     pgtype.Text
	ParserVersion   pgtype.Text
	LocationSummary pgtype.Text
	Display         []byte
	Metadata        []byte
}

func (r *pgFindingRepo) CreateOccurrence(ctx context.Context, arg CreateOccurrenceParams) (sqlc.FindingOccurrence, error) {
	return r.q.CreateOccurrence(ctx, sqlc.CreateOccurrenceParams{
		FindingID:       arg.FindingID,
		ReportID:        arg.ReportID,
		Title:           arg.Title,
		Description:     arg.Description,
		Severity:        arg.Severity,
		SeverityRank:    arg.SeverityRank,
		Score:           arg.Score,
		ToolName:        arg.ToolName,
		ToolVersion:     arg.ToolVersion,
		ParserVersion:   arg.ParserVersion,
		LocationSummary: arg.LocationSummary,
		Display:         arg.Display,
		Metadata:        arg.Metadata,
		ObservedAt:      pgtype.Timestamptz{Time: time.Now(), Valid: true},
	})
}

type UpsertDimensionParams struct {
	FindingID pgtype.UUID
	Key       string
	Value     string
	Source    pgtype.Text
}

func (r *pgFindingRepo) UpsertDimension(ctx context.Context, arg UpsertDimensionParams) (sqlc.FindingDimension, error) {
	return r.q.UpsertDimension(ctx, sqlc.UpsertDimensionParams{
		FindingID: arg.FindingID,
		DimKey:    arg.Key,
		DimValue:  arg.Value,
		Source:    arg.Source,
	})
}

type GetByFingerprintParams struct {
	ProjectID   pgtype.UUID
	FindingKind string
	Fingerprint string
}

func (r *pgFindingRepo) GetByID(ctx context.Context, id pgtype.UUID) (sqlc.Finding, error) {
	return r.q.GetFindingByID(ctx, id)
}

func (r *pgFindingRepo) GetByFingerprint(ctx context.Context, arg GetByFingerprintParams) (sqlc.Finding, error) {
	return r.q.GetFindingByFingerprint(ctx, sqlc.GetFindingByFingerprintParams{
		ProjectID:   arg.ProjectID,
		FindingKind: arg.FindingKind,
		Fingerprint: arg.Fingerprint,
	})
}

func (r *pgFindingRepo) ListByIDs(ctx context.Context, ids []pgtype.UUID) ([]sqlc.Finding, error) {
	return r.q.ListFindingsByIDs(ctx, ids)
}

type UpdateAnalysisParams struct {
	ID                pgtype.UUID
	AnalysisState     string
	GateEffect        string
	AnalysisExpiresAt pgtype.Timestamptz
	AnalysisReason    pgtype.Text
	AnalysisSource    string
	ManualOverride    bool
	ReviewRequired    bool
	AnalysisUpdatedBy pgtype.UUID
}

func (r *pgFindingRepo) UpdateAnalysis(ctx context.Context, arg UpdateAnalysisParams) (sqlc.Finding, error) {
	return r.q.UpdateFindingAnalysis(ctx, sqlc.UpdateFindingAnalysisParams{
		ID:                arg.ID,
		AnalysisState:     arg.AnalysisState,
		GateEffect:        arg.GateEffect,
		AnalysisExpiresAt: arg.AnalysisExpiresAt,
		AnalysisReason:    arg.AnalysisReason,
		AnalysisSource:    arg.AnalysisSource,
		ManualOverride:    arg.ManualOverride,
		ReviewRequired:    arg.ReviewRequired,
		AnalysisUpdatedBy: arg.AnalysisUpdatedBy,
	})
}

type BulkUpdateAnalysisParams struct {
	IDs               []pgtype.UUID
	AnalysisState     string
	GateEffect        string
	AnalysisExpiresAt pgtype.Timestamptz
	AnalysisReason    pgtype.Text
	AnalysisSource    string
	ManualOverride    bool
	ReviewRequired    bool
	AnalysisUpdatedBy pgtype.UUID
}

func (r *pgFindingRepo) BulkUpdateAnalysis(ctx context.Context, arg BulkUpdateAnalysisParams) ([]sqlc.Finding, error) {
	return r.q.BulkUpdateFindingAnalysis(ctx, sqlc.BulkUpdateFindingAnalysisParams{
		Column1:           arg.IDs,
		AnalysisState:     arg.AnalysisState,
		GateEffect:        arg.GateEffect,
		AnalysisExpiresAt: arg.AnalysisExpiresAt,
		AnalysisReason:    arg.AnalysisReason,
		AnalysisSource:    arg.AnalysisSource,
		ManualOverride:    arg.ManualOverride,
		ReviewRequired:    arg.ReviewRequired,
		AnalysisUpdatedBy: arg.AnalysisUpdatedBy,
	})
}

type GateEvalParams struct {
	ProjectID       pgtype.UUID
	MinSeverityRank int16
}

func (r *pgFindingRepo) GateEval(ctx context.Context, arg GateEvalParams) (bool, error) {
	return r.q.GateEval(ctx, sqlc.GateEvalParams{
		ProjectID:           arg.ProjectID,
		CurrentSeverityRank: arg.MinSeverityRank,
	})
}

func (r *pgFindingRepo) CountBlocking(ctx context.Context, arg GateEvalParams) (int64, error) {
	return r.q.CountBlockingFindings(ctx, sqlc.CountBlockingFindingsParams{
		ProjectID:           arg.ProjectID,
		CurrentSeverityRank: arg.MinSeverityRank,
	})
}

type CreateEventParams struct {
	FindingID pgtype.UUID
	UserID    pgtype.UUID
	EventType string
	OldValue  pgtype.Text
	NewValue  pgtype.Text
	Comment   pgtype.Text
	Changes   []byte
}

func (r *pgFindingRepo) CreateEvent(ctx context.Context, arg CreateEventParams) (sqlc.FindingEvent, error) {
	return r.q.CreateFindingEvent(ctx, sqlc.CreateFindingEventParams{
		FindingID: arg.FindingID,
		UserID:    arg.UserID,
		EventType: arg.EventType,
		OldValue:  arg.OldValue,
		NewValue:  arg.NewValue,
		Comment:   arg.Comment,
		Changes:   arg.Changes,
	})
}

func (r *pgFindingRepo) ListEvents(ctx context.Context, findingID pgtype.UUID, eventTypes []string, limit, offset int32) ([]sqlc.FindingEvent, error) {
	return r.q.ListFindingEvents(ctx, sqlc.ListFindingEventsParams{
		FindingID: findingID,
		Column2:   eventTypes,
		Limit:     limit,
		Offset:    offset,
	})
}

func (r *pgFindingRepo) HasDimension(ctx context.Context, findingID pgtype.UUID, key string) (bool, error) {
	return r.q.HasDimension(ctx, sqlc.HasDimensionParams{
		FindingID: findingID,
		DimKey:    key,
	})
}
