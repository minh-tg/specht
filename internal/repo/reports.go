package repo

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
)

type pgReportRepo struct {
	q *sqlc.Queries
}

// CreateReportParams is the input to creating a report row.
type CreateReportParams struct {
	ProjectID        pgtype.UUID
	ToolName         string
	ToolVersion      pgtype.Text
	ScanType         string
	ScanTarget       pgtype.Text
	TargetID         pgtype.UUID
	ArtifactID       pgtype.UUID
	EnvironmentID    pgtype.UUID
	Branch           pgtype.Text
	CommitSha        pgtype.Text
	BaseRevision     pgtype.Text
	ChangedFiles     []byte
	ScanMode         string
	ScanScope        []byte
	ScanScopeHash    pgtype.Text
	RawData          []byte
	RawReportHash    pgtype.Text
	ParserVersion    pgtype.Text
	ScanCompleteness string
}

func (r *pgReportRepo) Create(ctx context.Context, arg CreateReportParams) (sqlc.Report, error) {
	changedFiles := arg.ChangedFiles
	if len(changedFiles) == 0 {
		changedFiles = []byte("[]")
	}
	return r.q.CreateReport(ctx, sqlc.CreateReportParams{
		ProjectID:        arg.ProjectID,
		ToolName:         arg.ToolName,
		ToolVersion:      arg.ToolVersion,
		ScanType:         arg.ScanType,
		ScanTarget:       arg.ScanTarget,
		TargetID:         arg.TargetID,
		ArtifactID:       arg.ArtifactID,
		EnvironmentID:    arg.EnvironmentID,
		ScanScope:        arg.ScanScope,
		ScanScopeHash:    arg.ScanScopeHash,
		Branch:           arg.Branch,
		CommitSha:        arg.CommitSha,
		BaseRevision:     arg.BaseRevision,
		ChangedFiles:     changedFiles,
		ScanMode:         orFull(arg.ScanMode),
		RawData:          arg.RawData,
		RawReportHash:    arg.RawReportHash,
		ParserVersion:    arg.ParserVersion,
		ScanCompleteness: orUnknown(arg.ScanCompleteness),
		Status:           "processing",
		StartedAt:        pgtype.Timestamptz{Time: time.Now(), Valid: true},
	})
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// orFull defaults an empty scan mode to a full scan. Unknown modes pass
// through for the reports_scan_mode_check constraint to reject.
func orFull(s string) string {
	if s == "" {
		return "full"
	}
	return s
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

func (r *pgReportRepo) LatestCompletedByScanner(ctx context.Context, projectID pgtype.UUID, toolName string) (sqlc.LatestCompletedReportByScannerRow, error) {
	return r.q.LatestCompletedReportByScanner(ctx, sqlc.LatestCompletedReportByScannerParams{
		ProjectID: projectID,
		ToolName:  toolName,
	})
}

func (r *pgReportRepo) GetCompletedByCommit(ctx context.Context, projectID pgtype.UUID, toolName string, commit pgtype.Text) (sqlc.GetCompletedReportByCommitRow, error) {
	return r.q.GetCompletedReportByCommit(ctx, sqlc.GetCompletedReportByCommitParams{
		ProjectID: projectID,
		ToolName:  toolName,
		CommitSha: commit,
	})
}

func (r *pgReportRepo) CountStaleReports(ctx context.Context, cutoff time.Time) (int64, error) {
	return r.q.CountStaleReports(ctx, uuidFromTime(cutoff))
}

func (r *pgReportRepo) DeleteStaleReports(ctx context.Context, cutoff time.Time) ([]pgtype.UUID, error) {
	return r.q.DeleteStaleReports(ctx, uuidFromTime(cutoff))
}

func (r *pgReportRepo) FindCompletedByHash(ctx context.Context, projectID pgtype.UUID, rawHash pgtype.Text) (pgtype.UUID, error) {
	return r.q.FindCompletedByHash(ctx, sqlc.FindCompletedByHashParams{
		ProjectID:     projectID,
		RawReportHash: rawHash,
	})
}

func (r *pgReportRepo) DeleteReport(ctx context.Context, id, projectID pgtype.UUID) error {
	return r.q.DeleteReport(ctx, sqlc.DeleteReportParams{
		ID:        id,
		ProjectID: projectID,
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
