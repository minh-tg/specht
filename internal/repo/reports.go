package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/vulnserve/vulnserve/internal/db/sqlc"
)

type pgReportRepo struct {
	q *sqlc.Queries
}

func newReportRepo(q *sqlc.Queries) *pgReportRepo {
	return &pgReportRepo{q: q}
}

type CreateReportParams struct {
	ProjectID       pgtype.UUID
	ToolName        string
	ToolVersion     pgtype.Text
	ScanType        string
	ScanTarget      pgtype.Text
	Branch          pgtype.Text
	CommitSha       pgtype.Text
	ScanScope       []byte
	RawReportHash   pgtype.Text
	ParserVersion   pgtype.Text
}

func (r *pgReportRepo) Create(ctx context.Context, arg CreateReportParams) (sqlc.Report, error) {
	return r.q.CreateReport(ctx, sqlc.CreateReportParams{
		ProjectID:       arg.ProjectID,
		ToolName:        arg.ToolName,
		ToolVersion:     arg.ToolVersion,
		ScanType:        arg.ScanType,
		ScanTarget:      arg.ScanTarget,
		ScanScope:       arg.ScanScope,
		Branch:          arg.Branch,
		CommitSha:       arg.CommitSha,
		RawReportHash:   arg.RawReportHash,
		ParserVersion:   arg.ParserVersion,
		ScanCompleteness: "unknown",
		Status:          "processing",
	})
}

func (r *pgReportRepo) GetByID(ctx context.Context, id pgtype.UUID) (sqlc.Report, error) {
	return r.q.GetReportByID(ctx, id)
}

func (r *pgReportRepo) ListByProject(ctx context.Context, projectID pgtype.UUID, limit, offset int32) ([]sqlc.Report, error) {
	return r.q.ListReportsByProject(ctx, sqlc.ListReportsByProjectParams{
		ProjectID: projectID,
		Limit:     limit,
		Offset:    offset,
	})
}

func (r *pgReportRepo) UpdateStatus(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error) {
	return r.q.UpdateReportStatus(ctx, sqlc.UpdateReportStatusParams{
		ID:            id,
		ProjectID:     projectID,
		Status:        status,
		TotalFindings: pgtype.Int4{Int32: int32(totalFindings), Valid: true},
		ErrorMessage:  errorMsg,
	})
}
