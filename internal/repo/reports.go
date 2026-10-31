package repo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

type pgReportRepo struct {
	q    *sqlc.Queries
	pool transactionStarter
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
	// CoveredFindingKinds are the finding kinds the report examined. Nil
	// stores NULL: the report vouches for no kind.
	CoveredFindingKinds []string
	// ExaminedKeys are the per-finding proofs the report carries. Nil stores
	// NULL.
	ExaminedKeys []string
}

func (r *pgReportRepo) Create(ctx context.Context, arg CreateReportParams) (sqlc.Report, error) {
	changedFiles := arg.ChangedFiles
	if len(changedFiles) == 0 {
		changedFiles = []byte("[]")
	}
	return r.q.CreateReport(ctx, sqlc.CreateReportParams{
		ProjectID:           arg.ProjectID,
		ToolName:            arg.ToolName,
		ToolVersion:         arg.ToolVersion,
		ScanType:            arg.ScanType,
		ScanTarget:          arg.ScanTarget,
		TargetID:            arg.TargetID,
		ArtifactID:          arg.ArtifactID,
		EnvironmentID:       arg.EnvironmentID,
		ScanScope:           arg.ScanScope,
		ScanScopeHash:       arg.ScanScopeHash,
		Branch:              arg.Branch,
		CommitSha:           arg.CommitSha,
		BaseRevision:        arg.BaseRevision,
		ChangedFiles:        changedFiles,
		ScanMode:            orFull(arg.ScanMode),
		RawData:             arg.RawData,
		RawReportHash:       arg.RawReportHash,
		ParserVersion:       arg.ParserVersion,
		ScanCompleteness:    orUnknown(arg.ScanCompleteness),
		Status:              "processing",
		StartedAt:           pgtype.Timestamptz{Time: time.Now(), Valid: true},
		CoveredFindingKinds: arg.CoveredFindingKinds,
		ExaminedKeys:        arg.ExaminedKeys,
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

func (r *pgReportRepo) ListByProject(ctx context.Context, projectID pgtype.UUID, filter port.ReportFilter, limit, offset int32) ([]sqlc.Report, error) {
	return r.q.ListReportsByProject(ctx, sqlc.ListReportsByProjectParams{
		ProjectID:    projectID,
		Branch:       filter.Branch,
		CommitSha:    filter.CommitSha,
		CommitPrefix: filter.CommitPrefix,
		Limit:        limit,
		Offset:       offset,
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

func (r *pgReportRepo) PreviousCompletedInScope(ctx context.Context, projectID, reportID pgtype.UUID) (pgtype.UUID, error) {
	return r.q.PreviousCompletedReportInScope(ctx, sqlc.PreviousCompletedReportInScopeParams{
		ProjectID: projectID,
		ReportID:  reportID,
	})
}

func (r *pgReportRepo) BranchHasChangeReport(ctx context.Context, projectID pgtype.UUID, branch string) (bool, error) {
	return r.q.BranchHasChangeReport(ctx, sqlc.BranchHasChangeReportParams{
		ProjectID: projectID,
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

// FailStaleReports settles the reports still processing since before the cutoff as failed,
// settles the half-written findings each one left, and returns how many reports it changed.
func (r *pgReportRepo) FailStaleReports(ctx context.Context, cutoff time.Time, reason string) (int64, error) {
	stale, err := r.q.FailStaleReports(ctx, sqlc.FailStaleReportsParams{
		CreatedAt:    uuidFromTime(cutoff),
		ErrorMessage: pgtype.Text{String: reason, Valid: true},
	})
	if err != nil {
		return 0, err
	}
	var settleErr error
	for _, report := range stale {
		if err := r.SettleFailedReport(ctx, report.ID, report.ProjectID); err != nil {
			settleErr = errors.Join(settleErr, fmt.Errorf("settle findings of report %s: %w", toUUID(report.ID), err))
		}
	}
	return int64(len(stale)), settleErr
}

// SettleFailedReport cleans up after an ingest that stopped midway: findings the failed report
// created that no occurrence supports are deleted, and the ones it only brought back or that
// were already triaged are archived. Both statements share one transaction, and running it again
// finds nothing. A report that is not failed is left alone.
func (r *pgReportRepo) SettleFailedReport(ctx context.Context, id, projectID pgtype.UUID) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	deleted, err := q.DeleteFindingsOfFailedReport(ctx, sqlc.DeleteFindingsOfFailedReportParams{ReportID: id, ProjectID: projectID})
	if err != nil {
		return fmt.Errorf("delete half-written findings: %w", err)
	}
	archived, err := q.ArchiveFindingsOfFailedReport(ctx, sqlc.ArchiveFindingsOfFailedReportParams{ReportID: id, ProjectID: projectID})
	if err != nil {
		return fmt.Errorf("archive half-written findings: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	if len(deleted)+len(archived) > 0 {
		slog.Warn("findings left by a failed report were settled",
			"report_id", toUUID(id), "deleted", len(deleted), "archived", len(archived))
	}
	return nil
}

// ClearRawDataBefore clears the raw_data payload of up to batchSize settled reports created before
// the cutoff and returns the ids it cleared.
func (r *pgReportRepo) ClearRawDataBefore(ctx context.Context, cutoff time.Time, batchSize int32) ([]pgtype.UUID, error) {
	ids, err := r.q.ClearRawDataBefore(ctx, sqlc.ClearRawDataBeforeParams{
		Cutoff:    uuidFromTime(cutoff),
		BatchSize: batchSize,
	})
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// DeleteStaleReports removes at most limit settled reports older than the
// cutoff, one transaction each, and returns the ids it removed. A report that
// a scan took back or someone else already deleted is skipped.
func (r *pgReportRepo) DeleteStaleReports(ctx context.Context, cutoff time.Time, limit int) ([]pgtype.UUID, error) {
	if limit <= 0 {
		return nil, fmt.Errorf("stale report limit must be positive, got %d", limit)
	}
	stale, err := r.q.ListStaleReports(ctx, sqlc.ListStaleReportsParams{CompletedAt: uuidFromTime(cutoff), BatchSize: int32(limit)})
	if err != nil {
		return nil, err
	}
	deleted := make([]pgtype.UUID, 0, len(stale))
	for _, report := range stale {
		_, err := r.DeleteReportAndSettle(ctx, report.ID, report.ProjectID, pgtype.UUID{})
		if errors.Is(err, port.ErrNotFound) || errors.Is(err, port.ErrReportProcessing) {
			continue
		}
		if err != nil {
			return deleted, fmt.Errorf("delete report %s: %w", toUUID(report.ID), err)
		}
		deleted = append(deleted, report.ID)
	}
	return deleted, nil
}

// DeleteReportAndSettle deletes a report and settles the findings it was
// evidence for, in one transaction. See port.ReportStore.
func (r *pgReportRepo) DeleteReportAndSettle(ctx context.Context, id, projectID, actor pgtype.UUID) (port.ReportDeletion, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return port.ReportDeletion{}, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := sqlc.New(tx)

	status, err := q.LockReportForDelete(ctx, sqlc.LockReportForDeleteParams{ID: id, ProjectID: projectID})
	if errors.Is(err, pgx.ErrNoRows) {
		return port.ReportDeletion{}, port.ErrNotFound
	}
	if err != nil {
		return port.ReportDeletion{}, fmt.Errorf("lock report: %w", err)
	}
	if status != "completed" && status != "failed" {
		return port.ReportDeletion{}, port.ErrReportProcessing
	}

	scopeHash, err := q.ReportScanScopeHash(ctx, sqlc.ReportScanScopeHashParams{ID: id, ProjectID: projectID})
	if err != nil {
		return port.ReportDeletion{}, fmt.Errorf("read report scope: %w", err)
	}

	touched, err := q.ListFindingsTouchedByReport(ctx, sqlc.ListFindingsTouchedByReportParams{ReportID: id, ProjectID: projectID})
	if err != nil {
		return port.ReportDeletion{}, fmt.Errorf("list findings touched by report: %w", err)
	}
	all := make([]pgtype.UUID, len(touched))
	var introduced []pgtype.UUID
	for i, f := range touched {
		all[i] = f.ID
		if f.Introduced {
			introduced = append(introduced, f.ID)
		}
	}
	// Ingest writes severity while holding the finding's row lock. Taking the
	// same locks in id order makes a concurrent scoped upsert wait, so the
	// recompute below cannot delete a scope row it just wrote.
	if _, err := q.LockFindingsByIDs(ctx, all); err != nil {
		return port.ReportDeletion{}, fmt.Errorf("lock findings touched by report: %w", err)
	}

	if err := q.DeleteReport(ctx, sqlc.DeleteReportParams{ID: id, ProjectID: projectID}); err != nil {
		return port.ReportDeletion{}, fmt.Errorf("delete report: %w", err)
	}
	// The deleted report no longer supplies this scope's severity. Remaining
	// reports in the same scope take over, or the row goes when none is left.
	retire := sqlc.RetireScopeSeverityWithoutEvidenceParams{FindingIds: all, ScopeHash: scopeHash}
	if err := q.RetireScopeSeverityWithoutEvidence(ctx, retire); err != nil {
		return port.ReportDeletion{}, fmt.Errorf("retire deleted report's scope severity: %w", err)
	}
	restore := sqlc.RestoreScopeSeverityFromNewestEvidenceParams{FindingIds: all, ScopeHash: scopeHash}
	if err := q.RestoreScopeSeverityFromNewestEvidence(ctx, restore); err != nil {
		return port.ReportDeletion{}, fmt.Errorf("restore scope severity from remaining reports: %w", err)
	}
	if len(all) > 0 {
		if err := q.RefreshFindingScopeSeverities(ctx, all); err != nil {
			return port.ReportDeletion{}, fmt.Errorf("refresh finding severity: %w", err)
		}
	}
	archived, err := q.ArchiveOrphanedFindings(ctx, sqlc.ArchiveOrphanedFindingsParams{
		FindingIds: all, ActorID: actor, ReportID: toUUID(id),
	})
	if err != nil {
		return port.ReportDeletion{}, fmt.Errorf("archive orphaned findings: %w", err)
	}
	if len(introduced) > 0 {
		if _, err := q.RepointIntroducedBy(ctx, introduced); err != nil {
			return port.ReportDeletion{}, fmt.Errorf("repoint attribution: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return port.ReportDeletion{}, fmt.Errorf("commit: %w", err)
	}
	return port.ReportDeletion{ArchivedFindings: len(archived)}, nil
}

// ReportDeletionImpact reads what DeleteReportAndSettle would settle.
func (r *pgReportRepo) ReportDeletionImpact(ctx context.Context, id, projectID pgtype.UUID) (port.ReportDeletionImpact, error) {
	row, err := r.q.ReportDeletionImpact(ctx, sqlc.ReportDeletionImpactParams{ReportID: id, ProjectID: projectID})
	if err != nil {
		return port.ReportDeletionImpact{}, fmt.Errorf("read report deletion impact: %w", err)
	}
	if row.Found == 0 {
		return port.ReportDeletionImpact{}, port.ErrNotFound
	}
	return port.ReportDeletionImpact{
		AffectedFindings: int(row.AffectedFindings),
		ArchivedFindings: int(row.ArchivedFindings),
	}, nil
}

func (r *pgReportRepo) FindCompletedByReplayKey(ctx context.Context, projectID pgtype.UUID, rawHash, commitSha, scopeHash pgtype.Text) (pgtype.UUID, error) {
	return r.q.FindCompletedByReplayKey(ctx, sqlc.FindCompletedByReplayKeyParams{
		ProjectID:     projectID,
		RawReportHash: rawHash,
		CommitSha:     commitSha,
		ScanScopeHash: scopeHash,
	})
}

func (r *pgReportRepo) DeleteReport(ctx context.Context, id, projectID pgtype.UUID) error {
	return r.q.DeleteReport(ctx, sqlc.DeleteReportParams{
		ID:        id,
		ProjectID: projectID,
	})
}

// DeleteDuplicateReport removes a duplicate-race loser and moves the finding
// attribution it introduced to the winner. Both statements share one
// transaction so a crash cannot leave a finding pointing at a deleted report;
// the loser's report_introduced_findings rows cascade with it and the
// winner's own rows are untouched.
func (r *pgReportRepo) DeleteDuplicateReport(ctx context.Context, id, projectID, winnerID pgtype.UUID) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() {
		_ = tx.Rollback(ctx)
	}()

	q := sqlc.New(tx)
	touched, err := q.ListFindingsTouchedByReport(ctx, sqlc.ListFindingsTouchedByReportParams{ReportID: id, ProjectID: projectID})
	if err != nil {
		return err
	}
	ids := make([]pgtype.UUID, len(touched))
	for i, f := range touched {
		ids[i] = f.ID
	}
	if _, err := q.LockFindingsByIDs(ctx, ids); err != nil {
		return err
	}
	if err := q.RepointDuplicateScopeSeverity(ctx, sqlc.RepointDuplicateScopeSeverityParams{LoserID: id, WinnerID: winnerID, ProjectID: projectID}); err != nil {
		return fmt.Errorf("repoint duplicate scope: %w", err)
	}
	if err := q.ReassignFindingIntroducedBy(ctx, sqlc.ReassignFindingIntroducedByParams{
		ProjectID:              projectID,
		IntroducedByReportID:   id,
		IntroducedByReportID_2: winnerID,
	}); err != nil {
		return fmt.Errorf("reassign finding attribution: %w", err)
	}
	if err := q.DeleteReport(ctx, sqlc.DeleteReportParams{
		ID:        id,
		ProjectID: projectID,
	}); err != nil {
		return fmt.Errorf("delete duplicate report: %w", err)
	}
	return tx.Commit(ctx)
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
