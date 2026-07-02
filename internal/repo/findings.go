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
	ProjectID        pgtype.UUID
	FindingKind      string
	Fingerprint      string
	CurrentTitle     string
	Severity         string
	SeverityRank     int16
	Score            pgtype.Numeric
	FirstSeenAt      pgtype.Timestamptz
	LastSeenAt       pgtype.Timestamptz
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
		State:              "open",
		TriageStatus:       "untriaged",
		FirstSeenAt:        arg.FirstSeenAt,
		LastSeenAt:         arg.LastSeenAt,
	})
}

type CreateOccurrenceParams struct {
	FindingID      pgtype.UUID
	ReportID       pgtype.UUID
	Title          string
	Description    pgtype.Text
	Severity       string
	SeverityRank   int16
	Score          pgtype.Numeric
	ToolName       string
	ToolVersion    pgtype.Text
	ParserVersion  pgtype.Text
	LocationSummary pgtype.Text
	Display        []byte
	Metadata       []byte
}

func (r *pgFindingRepo) CreateOccurrence(ctx context.Context, arg CreateOccurrenceParams) (sqlc.FindingOccurrence, error) {
	return r.q.CreateOccurrence(ctx, sqlc.CreateOccurrenceParams{
		FindingID:      arg.FindingID,
		ReportID:       arg.ReportID,
		Title:          arg.Title,
		Description:    arg.Description,
		Severity:       arg.Severity,
		SeverityRank:   arg.SeverityRank,
		Score:          arg.Score,
		ToolName:       arg.ToolName,
		ToolVersion:    arg.ToolVersion,
		ParserVersion:  arg.ParserVersion,
		LocationSummary: arg.LocationSummary,
		Display:        arg.Display,
		Metadata:       arg.Metadata,
		ObservedAt:     pgtype.Timestamptz{Time: time.Now(), Valid: true},
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
