package repo

import (
	"context"
	"fmt"
	"math"
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

func (r *pgReportRepo) HasCompletedReportForCommit(ctx context.Context, projectID pgtype.UUID, commit pgtype.Text) (bool, error) {
	return r.q.HasCompletedReportForCommit(ctx, sqlc.HasCompletedReportForCommitParams{
		ProjectID: projectID,
		CommitSha: commit,
	})
}

func (r *pgReportRepo) GetLatestFullByBranch(ctx context.Context, projectID pgtype.UUID, toolName string, branch pgtype.Text) (sqlc.GetLatestCompletedFullReportByBranchRow, error) {
	return r.q.GetLatestCompletedFullReportByBranch(ctx, sqlc.GetLatestCompletedFullReportByBranchParams{
		ProjectID: projectID,
		ToolName:  toolName,
		Branch:    branch,
	})
}

func (r *pgReportRepo) LatestCompletedInFindingScope(ctx context.Context, projectID, findingID pgtype.UUID) (sqlc.LatestCompletedFullReportInFindingScopeRow, error) {
	return r.q.LatestCompletedFullReportInFindingScope(ctx, sqlc.LatestCompletedFullReportInFindingScopeParams{
		ProjectID: projectID,
		FindingID: findingID,
	})
}

func (r *pgReportRepo) CountStaleReports(ctx context.Context, cutoff time.Time) (int64, error) {
	return r.q.CountStaleReports(ctx, uuidFromTime(cutoff))
}

func (r *pgReportRepo) DeleteStaleReports(ctx context.Context, cutoff time.Time) ([]pgtype.UUID, error) {
	return r.q.DeleteStaleReports(ctx, uuidFromTime(cutoff))
}

func (r *pgReportRepo) FindCompletedByHashAndCommit(ctx context.Context, projectID pgtype.UUID, rawHash, commitSha pgtype.Text) (pgtype.UUID, error) {
	return r.q.FindCompletedByHashAndCommit(ctx, sqlc.FindCompletedByHashAndCommitParams{
		ProjectID:     projectID,
		RawReportHash: rawHash,
		CommitSha:     commitSha,
	})
}

func (r *pgReportRepo) DeleteReport(ctx context.Context, id, projectID pgtype.UUID) error {
	return r.q.DeleteReport(ctx, sqlc.DeleteReportParams{
		ID:        id,
		ProjectID: projectID,
	})
}

func (r *pgReportRepo) UpdateStatus(ctx context.Context, id, projectID pgtype.UUID, status string, totalFindings int, errorMsg pgtype.Text) (sqlc.Report, error) {
	count, err := int32Count(totalFindings)
	if err != nil {
		return sqlc.Report{}, err
	}

	return r.q.UpdateReportStatus(ctx, sqlc.UpdateReportStatusParams{
		ID:            id,
		ProjectID:     projectID,
		Status:        status,
		TotalFindings: pgtype.Int4{Int32: count, Valid: true},
		ErrorMessage:  errorMsg,
	})
}

func int32Count(count int) (int32, error) {
	if count < math.MinInt32 || count > math.MaxInt32 {
		return 0, fmt.Errorf("total findings count %d overflows int32", count)
	}
	return int32(count), nil
}
