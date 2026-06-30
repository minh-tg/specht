package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/vulnserve/vulnserve/internal/db/sqlc"
)

type FindingRepo struct {
	q *sqlc.Queries
}

func NewFindingRepo(q *sqlc.Queries) *FindingRepo {
	return &FindingRepo{q: q}
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

func (r *FindingRepo) Upsert(ctx context.Context, arg UpsertFindingParams) (sqlc.Finding, error) {
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

func (r *FindingRepo) CreateOccurrence(ctx context.Context, arg CreateOccurrenceParams) (sqlc.FindingOccurrence, error) {
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
	})
}

type UpsertDimensionParams struct {
	FindingID pgtype.UUID
	Key       string
	Value     string
	Source    pgtype.Text
}

func (r *FindingRepo) UpsertDimension(ctx context.Context, arg UpsertDimensionParams) (sqlc.FindingDimension, error) {
	return r.q.UpsertDimension(ctx, sqlc.UpsertDimensionParams{
		FindingID: arg.FindingID,
		DimKey:    arg.Key,
		DimValue:  arg.Value,
		Source:    arg.Source,
	})
}
