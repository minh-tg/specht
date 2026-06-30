package repo

import (
	"context"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/vulnserve/vulnserve/internal/db/sqlc"
)

type ReportRepo struct {
	q *sqlc.Queries
}

func NewReportRepo(q *sqlc.Queries) *ReportRepo {
	return &ReportRepo{q: q}
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

func (r *ReportRepo) Create(ctx context.Context, arg CreateReportParams) (sqlc.Report, error) {
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

func (r *ReportRepo) GetByID(ctx context.Context, id pgtype.UUID) (sqlc.Report, error) {
	return r.q.GetReportByID(ctx, id)
}

func (r *ReportRepo) UpdateStatus(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error) {
	return r.q.UpdateReportStatus(ctx, sqlc.UpdateReportStatusParams{
		ID:            id,
		ProjectID:     projectID,
		Status:        status,
		TotalFindings: pgtype.Int4{Int32: int32(totalFindings), Valid: true},
		ErrorMessage:  errorMsg,
	})
}
