package repo

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xMinhx/specht/internal/db/sqlc"
)

type pgFindingRepo struct {
	q    *sqlc.Queries
	pool *pgxpool.Pool
}

// UpsertFindingParams is the input to upserting a finding row.
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

func (r *pgFindingRepo) ListByProject(ctx context.Context, projectID pgtype.UUID, severities, states, kinds, environments, targets []string, limit, offset int32) ([]sqlc.Finding, error) {
	return r.q.ListFindingsByProject(ctx, sqlc.ListFindingsByProjectParams{
		ProjectID: projectID,
		Column2:   severities,
		Column3:   states,
		Column4:   kinds,
		Column5:   environments,
		Column6:   targets,
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

// CreateOccurrenceParams is the input to creating a finding occurrence.
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

// UpsertDimensionParams is the input to upserting a finding dimension.
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

func (r *pgFindingRepo) ListDimensions(ctx context.Context, findingID pgtype.UUID) ([]sqlc.ListFindingDimensionsRow, error) {
	return r.q.ListFindingDimensions(ctx, findingID)
}

// GetByFingerprintParams identifies a finding by project, kind, and fingerprint.
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

// UpdateAnalysisParams is the input to updating a finding's analysis state.
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

// BulkUpdateAnalysisParams is the input to a bulk analysis-state update.
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

// CreateEventParams is the input to creating a finding audit event.
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

// FindScaFindingIdForPurlAndCve resolves the sca finding that already covers
// the (name-level purl, candidate ids) pair for the CVE feed watcher's
// gap-fill check. It returns pgx.ErrNoRows when no scan-derived finding
// covers the pair.
func (r *pgFindingRepo) FindScaFindingIdForPurlAndCve(ctx context.Context, projectID pgtype.UUID, purlName string, candidateIDs []string) (pgtype.UUID, error) {
	return r.q.FindScaFindingIdForPurlAndCve(ctx, sqlc.FindScaFindingIdForPurlAndCveParams{
		ProjectID:    projectID,
		PurlName:     purlName,
		CandidateIds: candidateIDs,
	})
}

// FindingContext is the environment/target/artifact context of a finding.
type FindingContext struct {
	EnvironmentID pgtype.UUID
	TargetID      pgtype.UUID
	ArtifactID    pgtype.UUID
}

// GetFindingContext returns the environment/target/artifact context of the
// finding's most recent scan occurrence. It is the per-finding counterpart
// to the batch ListGateCandidates loader; prefer the batch query for gate
// evaluation.
func (r *pgFindingRepo) GetFindingContext(ctx context.Context, findingID pgtype.UUID) (FindingContext, error) {
	row, err := r.q.GetFindingContext(ctx, findingID)
	if err != nil {
		return FindingContext{}, err
	}
	return FindingContext{
		EnvironmentID: row.EnvironmentID,
		TargetID:      row.TargetID,
		ArtifactID:    row.ArtifactID,
	}, nil
}

// GetFindingDisplayContext returns the human-readable deployment context of
// the finding's most recent scan occurrence for detail views.
func (r *pgFindingRepo) GetFindingDisplayContext(ctx context.Context, findingID pgtype.UUID) (sqlc.GetFindingDisplayContextRow, error) {
	return r.q.GetFindingDisplayContext(ctx, findingID)
}

// PersistWatcherFindingParams carries everything needed to persist one
// watcher-created finding: the finding row, its dimensions, its occurrence
// (report_id NULL), the auto_rule_applied event, and the provenance evidence
// artifact. All are written in a single transaction.
type PersistWatcherFindingParams struct {
	Finding    sqlc.CreateFindingIfAbsentParams
	Dimensions []sqlc.UpsertDimensionParams
	Occurrence sqlc.CreateOccurrenceParams
	Event      *sqlc.CreateFindingEventParams
	Evidence   *sqlc.CreateEvidenceParams
}

// PersistWatcherFinding creates a cve_watcher finding and its dependent rows
// atomically. When the finding fingerprint already exists (a re-poll hit),
// the insert returns pgx.ErrNoRows and PersistWatcherFinding reports
// created=false with no changes — the caller counts that as unchanged.
func (r *pgFindingRepo) PersistWatcherFinding(ctx context.Context, arg PersistWatcherFindingParams) (sqlc.Finding, bool, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return sqlc.Finding{}, false, fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	q := sqlc.New(tx)
	f, err := q.CreateFindingIfAbsent(ctx, arg.Finding)
	if errors.Is(err, pgx.ErrNoRows) {
		return sqlc.Finding{}, false, nil // re-poll hit: nothing to do
	}
	if err != nil {
		return sqlc.Finding{}, false, fmt.Errorf("create finding: %w", err)
	}

	for _, d := range arg.Dimensions {
		d.FindingID = f.ID
		if _, err := q.UpsertDimension(ctx, d); err != nil {
			return sqlc.Finding{}, false, fmt.Errorf("upsert dimension: %w", err)
		}
	}

	occ := arg.Occurrence
	occ.FindingID = f.ID
	if _, err := q.CreateOccurrence(ctx, occ); err != nil {
		return sqlc.Finding{}, false, fmt.Errorf("create occurrence: %w", err)
	}

	if arg.Event != nil {
		ev := *arg.Event
		ev.FindingID = f.ID
		if _, err := q.CreateFindingEvent(ctx, ev); err != nil {
			return sqlc.Finding{}, false, fmt.Errorf("create event: %w", err)
		}
	}

	if arg.Evidence != nil {
		ev := *arg.Evidence
		ev.FindingID = f.ID
		if _, err := q.CreateEvidence(ctx, ev); err != nil {
			return sqlc.Finding{}, false, fmt.Errorf("create evidence: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return sqlc.Finding{}, false, fmt.Errorf("commit tx: %w", err)
	}
	return f, true, nil
}

// PersistWatcherSkipEvent appends an audit event to an existing finding (the
// suppressing finding for a skipped watcher pair).
func (r *pgFindingRepo) PersistWatcherSkipEvent(ctx context.Context, arg sqlc.CreateFindingEventParams) error {
	_, err := r.q.CreateFindingEvent(ctx, arg)
	if err != nil {
		return fmt.Errorf("create skip event: %w", err)
	}
	return nil
}

func (r *pgFindingRepo) ListBlockingFindings(ctx context.Context, projectID pgtype.UUID, minSeverityRank int16) ([]sqlc.Finding, error) {
	// Batch gate-candidate loader: one round trip returns the candidates with
	// their context and latest reachability (see ListGateCandidates in
	// findings.sql). This repo method is the legacy sqlc-row surface; the
	// port FindingStore maps rows to port.Finding for the gate.
	rows, err := r.ListGateCandidates(ctx, projectID, minSeverityRank)
	if err != nil {
		return nil, err
	}
	items := make([]sqlc.Finding, 0, len(rows))
	for _, row := range rows {
		items = append(items, sqlc.Finding{
			ID:                  row.ID,
			ProjectID:           row.ProjectID,
			FindingKind:         row.FindingKind,
			Fingerprint:         row.Fingerprint,
			CurrentTitle:        row.CurrentTitle,
			CurrentSeverityRank: row.CurrentSeverityRank,
			AnalysisState:       row.AnalysisState,
		})
	}
	return items, nil
}

// ListGateCandidates returns the batch gate-candidate rows (context +
// latest reachability in one round trip).
func (r *pgFindingRepo) ListGateCandidates(ctx context.Context, projectID pgtype.UUID, minSeverityRank int16) ([]sqlc.ListGateCandidatesRow, error) {
	return r.q.ListGateCandidates(ctx, sqlc.ListGateCandidatesParams{
		ProjectID:           projectID,
		CurrentSeverityRank: minSeverityRank,
	})
}
