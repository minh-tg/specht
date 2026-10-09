package repo

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"time"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/minh-tg/specht/internal/db/sqlc"
	"github.com/minh-tg/specht/internal/port"
)

// pgReportPort adapts ReportStore over the existing pgReportRepo.
type pgReportPort struct{ inner *pgReportRepo }

func newReportPort(r *pgReportRepo) *pgReportPort { return &pgReportPort{inner: r} }

func (r *pgReportPort) Create(ctx context.Context, input port.CreateReportInput) (port.Report, error) {
	pid, err := parseID(input.ProjectID)
	if err != nil {
		return port.Report{}, err
	}
	completeness := input.ScanCompleteness
	if completeness == "" {
		completeness = "unknown"
	}
	row, err := r.inner.Create(ctx, CreateReportParams{
		ProjectID:        pid,
		ToolName:         input.ToolName,
		ToolVersion:      textPtrFromString(input.ToolVersion),
		ScanType:         input.ScanType,
		ScanTarget:       textPtrFromString(input.ScanTarget),
		TargetID:         uuidPtrFromString(&input.TargetID),
		ArtifactID:       uuidPtrFromString(&input.ArtifactID),
		EnvironmentID:    uuidPtrFromString(&input.EnvironmentID),
		ScanScope:        input.ScanScope,
		ScanScopeHash:    textPtrFromString(&input.ScanScopeHash),
		Branch:           textPtrFromString(input.Branch),
		CommitSha:        textPtrFromString(input.CommitSha),
		BaseRevision:     textPtrFromString(input.BaseRevision),
		ChangedFiles:     changedFilesParam(input.ChangedFiles),
		ScanMode:         scanModeParam(input.ScanMode),
		RawData:          input.RawData,
		RawReportHash:    textPtrFromString(&input.RawReportHash),
		ParserVersion:    textPtrFromString(input.ParserVersion),
		ScanCompleteness: completeness,
	})
	if err != nil {
		// The duplicate-report unique violation (23505 on the raw-content
		// hash) is a port-level outcome: translate it here so the core
		// checks errors.Is(err, port.ErrDuplicateReport) without importing
		// pgconn.
		if isDuplicateReport(err) {
			return port.Report{}, port.ErrDuplicateReport
		}
		return port.Report{}, err
	}
	return reportRowToPort(row), nil
}

// isDuplicateReport reports whether err is a PostgreSQL unique-violation on
// the report row (raw-content hash collision).
func isDuplicateReport(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code == "23505"
	}
	return false
}

func (r *pgReportPort) GetByID(ctx context.Context, id string) (port.Report, error) {
	rid, err := parseID(id)
	if err != nil {
		return port.Report{}, err
	}
	row, err := r.inner.GetByID(ctx, rid)
	if err != nil {
		return port.Report{}, mappingErr(err)
	}
	return reportRowToPort(row), nil
}

func (r *pgReportPort) ListByProject(ctx context.Context, projectID string, limit, offset int32) ([]port.Report, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListByProject(ctx, pid, limit, offset)
	if err != nil {
		return nil, err
	}
	out := make([]port.Report, len(rows))
	for i, row := range rows {
		out[i] = reportRowToPort(row)
	}
	return out, nil
}

func (r *pgReportPort) LatestCompletedByScanner(ctx context.Context, projectID, scanner string) (port.CompletedReport, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.CompletedReport{}, err
	}
	row, err := r.inner.LatestCompletedByScanner(ctx, pid, scanner)
	if err != nil {
		return port.CompletedReport{}, mappingErr(err)
	}
	return port.CompletedReport{
		ID:           toUUID(row.ID),
		ToolName:     row.ToolName,
		Branch:       stringFromTextPtr(row.Branch),
		CommitSha:    stringFromTextPtr(row.CommitSha),
		Completeness: row.ScanCompleteness,
		CreatedAt:    row.CreatedAt.Time,
	}, nil
}

func (r *pgReportPort) HasCompletedForCommit(ctx context.Context, projectID, commit string) (bool, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return false, err
	}
	found, err := r.inner.HasCompletedReportForCommit(ctx, pid, textPtrFromString(&commit))
	if err != nil {
		return false, mappingErr(err)
	}
	return found, nil
}

func (r *pgReportPort) GetCompletedByCommit(ctx context.Context, projectID, scanner, commit string) (port.CompletedReport, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.CompletedReport{}, err
	}
	row, err := r.inner.GetCompletedByCommit(ctx, pid, scanner, textPtrFromString(&commit))
	if err != nil {
		return port.CompletedReport{}, mappingErr(err)
	}
	return port.CompletedReport{
		ID:           toUUID(row.ID),
		ToolName:     row.ToolName,
		Branch:       stringFromTextPtr(row.Branch),
		CommitSha:    stringFromTextPtr(row.CommitSha),
		BaseRevision: stringFromTextPtr(row.BaseRevision),
		ScanMode:     row.ScanMode,
		Completeness: row.ScanCompleteness,
		CreatedAt:    row.CreatedAt.Time,
	}, nil
}

func (r *pgReportPort) GetLatestFullByBranch(ctx context.Context, projectID, scanner, branch string) (port.CompletedReport, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.CompletedReport{}, err
	}
	row, err := r.inner.GetLatestFullByBranch(ctx, pid, scanner, textPtrFromString(&branch))
	if err != nil {
		return port.CompletedReport{}, mappingErr(err)
	}
	return port.CompletedReport{
		ID:           toUUID(row.ID),
		ToolName:     row.ToolName,
		Branch:       stringFromTextPtr(row.Branch),
		CommitSha:    stringFromTextPtr(row.CommitSha),
		BaseRevision: stringFromTextPtr(row.BaseRevision),
		ScanMode:     row.ScanMode,
		Completeness: row.ScanCompleteness,
		CreatedAt:    row.CreatedAt.Time,
	}, nil
}

// scanModeParam normalizes the requested scan mode for storage: empty
// means full, anything else passes through for the DB check constraint
// to accept ("full", "incremental") or reject with a clear error.
func scanModeParam(mode string) string {
	if mode == "" {
		return "full"
	}
	return mode
}

// changedFilesParam encodes the covered-path list for the JSONB column.
// Empty encodes as [] (never NULL) so readers never branch on null.
func changedFilesParam(files json.RawMessage) []byte {
	if len(files) == 0 {
		return []byte("[]")
	}
	return []byte(files)
}

func (r *pgReportPort) UpdateStatus(ctx context.Context, id, projectID, status string, totalFindings int32, errorMessage *string) (port.Report, error) {
	rid, err := parseID(id)
	if err != nil {
		return port.Report{}, err
	}
	pid, err := parseID(projectID)
	if err != nil {
		return port.Report{}, err
	}
	row, err := r.inner.UpdateStatus(ctx, rid, pid, status, int(totalFindings), textPtrFromString(errorMessage))
	if err != nil {
		// A 23505 here is the duplicate-content race: two identical
		// ingests both passed the pre-check, and the partial dedup index
		// admits the loser only at completion. Translate it like Create
		// does so callers see ErrDuplicateReport, not a raw constraint.
		if isDuplicateReport(err) {
			return port.Report{}, port.ErrDuplicateReport
		}
		return port.Report{}, err
	}
	return reportRowToPort(row), nil
}

func (r *pgReportPort) CountStaleReports(ctx context.Context, cutoff time.Time) (int64, error) {
	return r.inner.CountStaleReports(ctx, cutoff)
}

func (r *pgReportPort) DeleteStaleReports(ctx context.Context, cutoff time.Time) ([]string, error) {
	ids, err := r.inner.DeleteStaleReports(ctx, cutoff)
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = toUUID(id)
	}
	return out, nil
}

func (r *pgReportPort) FindCompletedByHash(ctx context.Context, projectID, rawHash string) (string, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return "", err
	}
	id, err := r.inner.FindCompletedByHash(ctx, pid, textPtrFromString(&rawHash))
	if err != nil {
		return "", mappingErr(err)
	}
	return toUUID(id), nil
}

func (r *pgReportPort) DeleteReport(ctx context.Context, id, projectID string) error {
	rid, err := parseID(id)
	if err != nil {
		return err
	}
	pid, err := parseID(projectID)
	if err != nil {
		return err
	}
	return mappingErr(r.inner.DeleteReport(ctx, rid, pid))
}

// ---------- Findings port over the existing repo methods ----------

const findingIngestBatchSize = 500

type pgFindingPort struct{ inner *pgFindingRepo }

func newFindingPort(r *pgFindingRepo) *pgFindingPort { return &pgFindingPort{inner: r} }

func (r *pgFindingPort) Upsert(ctx context.Context, input port.UpsertFindingInput) (port.Finding, error) {
	pid, err := parseID(input.ProjectID)
	if err != nil {
		return port.Finding{}, err
	}
	row, err := r.inner.Upsert(ctx, UpsertFindingParams{
		ProjectID:    pid,
		FindingKind:  input.FindingKind,
		Fingerprint:  input.Fingerprint,
		CurrentTitle: input.Title,
		Severity:     input.Severity,
		SeverityRank: input.SeverityRank,
		Score:        floatToNumeric(input.Score),
		FirstSeenAt:  uuidFromTime(input.FirstSeen),
		LastSeenAt:   uuidFromTime(input.LastSeen),
	})
	if err != nil {
		return port.Finding{}, err
	}
	return findingRowToPort(row), nil
}

func (r *pgFindingPort) GetByID(ctx context.Context, id string) (port.Finding, error) {
	fid, err := parseID(id)
	if err != nil {
		return port.Finding{}, err
	}
	row, err := r.inner.GetByID(ctx, fid)
	if err != nil {
		return port.Finding{}, mappingErr(err)
	}
	return findingRowToPort(row), nil
}

func (r *pgFindingPort) GetByFingerprint(ctx context.Context, projectID, findingKind, fingerprint string) (port.Finding, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.Finding{}, err
	}
	row, err := r.inner.GetByFingerprint(ctx, GetByFingerprintParams{
		ProjectID:   pid,
		FindingKind: findingKind,
		Fingerprint: fingerprint,
	})
	if err != nil {
		return port.Finding{}, mappingErr(err)
	}
	return findingRowToPort(row), nil
}

func (r *pgFindingPort) ListByIDs(ctx context.Context, ids []string) ([]port.Finding, error) {
	uids := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		uid, err := parseID(id)
		if err != nil {
			return nil, err
		}
		uids[i] = uid
	}
	rows, err := r.inner.ListByIDs(ctx, uids)
	if err != nil {
		return nil, err
	}
	out := make([]port.Finding, len(rows))
	for i, row := range rows {
		out[i] = findingRowToPort(row)
	}
	return out, nil
}

func (r *pgFindingPort) ListByProject(ctx context.Context, projectID string, params port.ListFindingsParams) ([]port.Finding, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListByProject(ctx, pid, params)
	if err != nil {
		return nil, err
	}
	out := make([]port.Finding, len(rows))
	for i, row := range rows {
		out[i] = findingRowToPort(row)
	}
	return out, nil
}

// CountByProject counts what ListByProject would return across all pages.
func (r *pgFindingPort) CountByProject(ctx context.Context, projectID string, params port.ListFindingsParams) (int64, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return 0, err
	}
	return r.inner.CountByProject(ctx, pid, params)
}

func (r *pgFindingPort) UpdateAnalysis(ctx context.Context, input port.UpdateAnalysisInput) (port.Finding, error) {
	fid, err := parseID(input.ID)
	if err != nil {
		return port.Finding{}, err
	}
	row, err := r.inner.UpdateAnalysis(ctx, UpdateAnalysisParams{
		ID:                fid,
		AnalysisState:     input.AnalysisState,
		GateEffect:        input.GateEffect,
		AnalysisExpiresAt: timestamptzPtrFromTime(input.AnalysisExpiresAt),
		AnalysisReason:    textPtrFromString(input.AnalysisReason),
		AnalysisSource:    input.AnalysisSource,
		ManualOverride:    input.ManualOverride,
		ReviewRequired:    input.ReviewRequired,
		AnalysisUpdatedBy: uuidPtrFromString(input.AnalysisUpdatedBy),
	})
	if err != nil {
		return port.Finding{}, mappingErr(err)
	}
	return findingRowToPort(row), nil
}

func (r *pgFindingPort) UpdateAnalysisWithEvent(ctx context.Context, input port.UpdateAnalysisInput, event port.FindingEventInput) (port.Finding, error) {
	fid, err := parseID(input.ID)
	if err != nil {
		return port.Finding{}, err
	}
	eventID, err := parseID(event.FindingID)
	if err != nil {
		return port.Finding{}, err
	}
	row, err := r.inner.UpdateAnalysisWithEvent(ctx, UpdateAnalysisParams{
		ID: fid, AnalysisState: input.AnalysisState, GateEffect: input.GateEffect,
		AnalysisExpiresAt: timestamptzPtrFromTime(input.AnalysisExpiresAt), AnalysisReason: textPtrFromString(input.AnalysisReason),
		AnalysisSource: input.AnalysisSource, ManualOverride: input.ManualOverride, ReviewRequired: input.ReviewRequired,
		AnalysisUpdatedBy: uuidPtrFromString(input.AnalysisUpdatedBy),
	}, CreateEventParams{
		FindingID: eventID, UserID: uuidPtrFromString(event.UserID), EventType: event.EventType,
		OldValue: textPtrFromString(event.OldValue), NewValue: textPtrFromString(event.NewValue), Comment: textPtrFromString(event.Comment), Changes: event.Changes,
	})
	if err != nil {
		return port.Finding{}, mappingErr(err)
	}
	return findingRowToPort(row), nil
}

func (r *pgFindingPort) BulkUpdateAnalysis(ctx context.Context, input port.UpdateAnalysisInput, ids []string) ([]port.Finding, error) {
	uids := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		uid, err := parseID(id)
		if err != nil {
			return nil, err
		}
		uids[i] = uid
	}
	rows, err := r.inner.BulkUpdateAnalysis(ctx, BulkUpdateAnalysisParams{
		IDs:               uids,
		AnalysisState:     input.AnalysisState,
		GateEffect:        input.GateEffect,
		AnalysisExpiresAt: timestamptzPtrFromTime(input.AnalysisExpiresAt),
		AnalysisReason:    textPtrFromString(input.AnalysisReason),
		AnalysisSource:    input.AnalysisSource,
		ManualOverride:    input.ManualOverride,
		ReviewRequired:    input.ReviewRequired,
		AnalysisUpdatedBy: uuidPtrFromString(input.AnalysisUpdatedBy),
	})
	if err != nil {
		return nil, err
	}
	out := make([]port.Finding, len(rows))
	for i, row := range rows {
		out[i] = findingRowToPort(row)
	}
	return out, nil
}

func (r *pgFindingPort) BulkTriage(ctx context.Context, input port.UpdateAnalysisInput, ids []string, event port.FindingEventInput) ([]port.Finding, error) {
	uids := make([]pgtype.UUID, len(ids))
	for i, id := range ids {
		uid, err := parseID(id)
		if err != nil {
			return nil, err
		}
		uids[i] = uid
	}
	eventUserID := pgtype.UUID{}
	if event.UserID != nil && *event.UserID != "" {
		uid, err := parseID(*event.UserID)
		if err != nil {
			return nil, err
		}
		eventUserID = uid
	}
	rows, err := r.inner.BulkTriage(ctx, BulkUpdateAnalysisParams{
		IDs:               uids,
		AnalysisState:     input.AnalysisState,
		GateEffect:        input.GateEffect,
		AnalysisExpiresAt: timestamptzPtrFromTime(input.AnalysisExpiresAt),
		AnalysisReason:    textPtrFromString(input.AnalysisReason),
		AnalysisSource:    input.AnalysisSource,
		ManualOverride:    input.ManualOverride,
		ReviewRequired:    input.ReviewRequired,
		AnalysisUpdatedBy: uuidPtrFromString(input.AnalysisUpdatedBy),
	}, CreateEventParams{
		UserID:    eventUserID,
		EventType: event.EventType,
		OldValue:  textPtrFromString(event.OldValue),
		NewValue:  textPtrFromString(event.NewValue),
		Comment:   textPtrFromString(event.Comment),
		Changes:   event.Changes,
	})
	if err != nil {
		return nil, err
	}
	out := make([]port.Finding, len(rows))
	for i, row := range rows {
		out[i] = findingRowToPort(row)
	}
	return out, nil
}

func (r *pgFindingPort) CreateEvent(ctx context.Context, input port.FindingEventInput) (port.FindingEvent, error) {
	fid, err := parseID(input.FindingID)
	if err != nil {
		return port.FindingEvent{}, err
	}
	row, err := r.inner.CreateEvent(ctx, CreateEventParams{
		FindingID: fid,
		UserID:    uuidPtrFromString(input.UserID),
		EventType: input.EventType,
		OldValue:  textPtrFromString(input.OldValue),
		NewValue:  textPtrFromString(input.NewValue),
		Comment:   textPtrFromString(input.Comment),
		Changes:   input.Changes,
	})
	if err != nil {
		return port.FindingEvent{}, err
	}
	return findingEventRowToPort(row), nil
}

// BulkCreateEvents writes one event shape for many findings in a single
// statement (FindingID is unused — every listed finding gets the event).
func (r *pgFindingPort) BulkCreateEvents(ctx context.Context, findingIDs []string, input port.FindingEventInput) error {
	if len(findingIDs) == 0 {
		return nil
	}
	ids := make([]pgtype.UUID, 0, len(findingIDs))
	for _, id := range findingIDs {
		fid, err := parseID(id)
		if err != nil {
			return err
		}
		ids = append(ids, fid)
	}
	return r.inner.BulkCreateFindingEvents(ctx, sqlc.BulkCreateFindingEventsParams{
		Column1:   ids,
		UserID:    uuidPtrFromString(input.UserID),
		EventType: input.EventType,
		OldValue:  textPtrFromString(input.OldValue),
		NewValue:  textPtrFromString(input.NewValue),
		Comment:   textPtrFromString(input.Comment),
		Changes:   input.Changes,
	})
}

func (r *pgFindingPort) ListEvents(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]port.FindingEvent, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListEvents(ctx, fid, eventTypes, limit, offset)
	if err != nil {
		return nil, err
	}
	out := make([]port.FindingEvent, len(rows))
	for i, row := range rows {
		out[i] = findingEventRowToPort(row)
	}
	return out, nil
}

func (r *pgFindingPort) HasDimension(ctx context.Context, findingID, key string) (bool, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return false, err
	}
	return r.inner.HasDimension(ctx, fid, key)
}

func (r *pgFindingPort) CreateOccurrence(ctx context.Context, input port.OccurrenceInput) (port.Occurrence, error) {
	fid, err := parseID(input.FindingID)
	if err != nil {
		return port.Occurrence{}, err
	}
	var rid pgtype.UUID
	if input.ReportID != nil {
		parsed, err := parseID(*input.ReportID)
		if err != nil {
			return port.Occurrence{}, err
		}
		rid = parsed
	}
	row, err := r.inner.CreateOccurrence(ctx, CreateOccurrenceParams{
		FindingID:       fid,
		ReportID:        rid,
		Title:           input.Title,
		Description:     textPtrFromString(input.Description),
		Severity:        input.Severity,
		SeverityRank:    input.SeverityRank,
		Score:           floatToNumeric(input.Score),
		ToolName:        input.ToolName,
		ToolVersion:     textPtrFromString(input.ToolVersion),
		ParserVersion:   textPtrFromString(input.ParserVersion),
		LocationSummary: textPtrFromString(input.LocationSummary),
		Display:         input.Display,
		Metadata:        input.Metadata,
	})
	if err != nil {
		return port.Occurrence{}, err
	}
	return port.Occurrence{
		ID:           toUUID(row.ID),
		FindingID:    toUUID(row.FindingID),
		ReportID:     stringPtrFromUUID(row.ReportID),
		Title:        row.Title,
		Severity:     row.Severity,
		SeverityRank: row.SeverityRank,
		ToolName:     row.ToolName,
		ObservedAt:   row.ObservedAt.Time,
	}, nil
}

func (r *pgFindingPort) BulkCreateOccurrences(ctx context.Context, occurrences []port.OccurrenceInput) error {
	if len(occurrences) == 0 {
		return nil
	}

	type occurrenceRecord struct {
		FindingID       string          `json:"finding_id"`
		ReportID        string          `json:"report_id"`
		Title           string          `json:"title"`
		Description     *string         `json:"description"`
		Severity        string          `json:"severity"`
		SeverityRank    int16           `json:"severity_rank"`
		Score           *float64        `json:"score"`
		ToolName        string          `json:"tool_name"`
		ToolVersion     *string         `json:"tool_version"`
		ParserVersion   *string         `json:"parser_version"`
		LocationSummary *string         `json:"location_summary"`
		SubjectSummary  *string         `json:"subject_summary"`
		Remediation     *string         `json:"remediation"`
		Display         json.RawMessage `json:"display"`
		Metadata        json.RawMessage `json:"metadata"`
	}

	records := make([]occurrenceRecord, 0, len(occurrences))
	seen := make(map[string]struct{}, len(occurrences))
	for _, occurrence := range occurrences {
		if occurrence.ReportID == nil || *occurrence.ReportID == "" {
			return errors.New("bulk occurrence requires a report ID")
		}
		findingID, err := parseID(occurrence.FindingID)
		if err != nil {
			return err
		}
		reportID, err := parseID(*occurrence.ReportID)
		if err != nil {
			return err
		}
		findingIDString := toUUID(findingID)
		reportIDString := toUUID(reportID)
		key := findingIDString + "\x00" + reportIDString
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		records = append(records, occurrenceRecord{
			FindingID:       findingIDString,
			ReportID:        reportIDString,
			Title:           occurrence.Title,
			Description:     stringFromTextPtr(textPtrFromString(occurrence.Description)),
			Severity:        occurrence.Severity,
			SeverityRank:    occurrence.SeverityRank,
			Score:           occurrenceScoreForJSON(occurrence.Score),
			ToolName:        occurrence.ToolName,
			ToolVersion:     stringFromTextPtr(textPtrFromString(occurrence.ToolVersion)),
			ParserVersion:   stringFromTextPtr(textPtrFromString(occurrence.ParserVersion)),
			LocationSummary: stringFromTextPtr(textPtrFromString(occurrence.LocationSummary)),
			SubjectSummary:  stringFromTextPtr(textPtrFromString(occurrence.SubjectSummary)),
			Remediation:     stringFromTextPtr(textPtrFromString(occurrence.Remediation)),
			Display:         occurrence.Display,
			Metadata:        occurrence.Metadata,
		})
	}

	for start := 0; start < len(records); start += findingIngestBatchSize {
		end := min(start+findingIngestBatchSize, len(records))
		payload, err := json.Marshal(records[start:end])
		if err != nil {
			return err
		}
		if err := r.inner.BulkInsertOccurrences(ctx, payload); err != nil {
			return err
		}
	}
	return nil
}

func (r *pgFindingPort) UpsertDimension(ctx context.Context, input port.DimensionInput) error {
	fid, err := parseID(input.FindingID)
	if err != nil {
		return err
	}
	_, err = r.inner.UpsertDimension(ctx, UpsertDimensionParams{
		FindingID: fid,
		Key:       input.Key,
		Value:     input.Value,
		Source:    textPtrFromString(input.Source),
	})
	return err
}

func occurrenceScoreForJSON(score float64) *float64 {
	numeric := floatToNumeric(score)
	if !numeric.Valid {
		return nil
	}
	value := float64(numeric.Int.Int64()) / 10
	return &value
}

func (r *pgFindingPort) BulkUpsertDimensions(ctx context.Context, source string, dimensions []port.DimensionInput) error {
	if len(dimensions) == 0 {
		return nil
	}

	findingIDs := make([]pgtype.UUID, 0, len(dimensions))
	keys := make([]string, 0, len(dimensions))
	values := make([]string, 0, len(dimensions))
	for _, dimension := range dimensions {
		findingID, err := parseID(dimension.FindingID)
		if err != nil {
			return err
		}
		findingIDs = append(findingIDs, findingID)
		keys = append(keys, dimension.Key)
		values = append(values, dimension.Value)
	}

	for start := 0; start < len(findingIDs); start += findingIngestBatchSize {
		end := min(start+findingIngestBatchSize, len(findingIDs))
		if err := r.inner.BulkUpsertDimensions(ctx, sqlc.BulkUpsertDimensionsParams{
			Source:     source,
			FindingIds: findingIDs[start:end],
			DimKeys:    keys[start:end],
			DimValues:  values[start:end],
		}); err != nil {
			return err
		}
	}
	return nil
}

func (r *pgFindingPort) ListDimensions(ctx context.Context, findingID string) ([]port.FindingDimension, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListDimensions(ctx, fid)
	if err != nil {
		return nil, err
	}
	out := make([]port.FindingDimension, len(rows))
	for i, row := range rows {
		out[i] = port.FindingDimension{Key: row.DimKey, Value: row.DimValue}
	}
	return out, nil
}

func (r *pgFindingPort) HasOccurrence(ctx context.Context, findingID, reportID string) (bool, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return false, err
	}
	rid, err := parseID(reportID)
	if err != nil {
		return false, err
	}
	return r.inner.HasOccurrence(ctx, fid, rid)
}

func (r *pgFindingPort) MarkFixed(ctx context.Context, findingID string) (port.Finding, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return port.Finding{}, err
	}
	row, err := r.inner.MarkFixed(ctx, fid)
	if err != nil {
		return port.Finding{}, mappingErr(err)
	}
	return findingRowToPort(row), nil
}

func (r *pgFindingPort) MarkFixedWithEvent(ctx context.Context, findingID string, event port.FindingEventInput) (port.Finding, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return port.Finding{}, err
	}
	eventID, err := parseID(event.FindingID)
	if err != nil {
		return port.Finding{}, err
	}
	row, err := r.inner.MarkFixedWithEvent(ctx, fid, CreateEventParams{
		FindingID: eventID, UserID: uuidPtrFromString(event.UserID), EventType: event.EventType,
		OldValue: textPtrFromString(event.OldValue), NewValue: textPtrFromString(event.NewValue), Comment: textPtrFromString(event.Comment), Changes: event.Changes,
	})
	if err != nil {
		return port.Finding{}, mappingErr(err)
	}
	return findingRowToPort(row), nil
}

// MarkAbsentFindingsFixed implements the scan-equivalence auto-fix writer:
// the SQL closes qualifying rows and returns them so the caller can log events.
func (r *pgFindingPort) MarkAbsentFindingsFixed(ctx context.Context, projectID, scopeHash, reportID string) ([]port.Finding, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rid, err := parseID(reportID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.MarkAbsentScopedFindingsFixed(ctx, sqlc.MarkAbsentScopedFindingsFixedParams{
		ProjectID:     pid,
		ScanScopeHash: textPtrFromString(&scopeHash),
		ReportID:      rid,
	})
	if err != nil {
		return nil, mappingErr(err)
	}
	findings := make([]port.Finding, 0, len(rows))
	for _, row := range rows {
		findings = append(findings, findingRowToPort(row))
	}
	return findings, nil
}

func (r *pgFindingPort) SetFindingIntroducedBy(ctx context.Context, findingID, reportID string, commitSha *string) (port.Finding, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return port.Finding{}, err
	}
	rid, err := parseID(reportID)
	if err != nil {
		return port.Finding{}, err
	}
	row, err := r.inner.SetIntroducedBy(ctx, fid, rid, textPtrFromString(commitSha))
	if err != nil {
		return port.Finding{}, mappingErr(err)
	}
	return findingRowToPort(row), nil
}

func (r *pgFindingPort) ListIntroducedByReport(ctx context.Context, projectID, reportID string) ([]port.Finding, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rid, err := parseID(reportID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListIntroducedByReport(ctx, pid, rid)
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]port.Finding, len(rows))
	for i, row := range rows {
		out[i] = findingRowToPort(row)
	}
	return out, nil
}

func (r *pgFindingPort) GetFindingContext(ctx context.Context, findingID string) (port.FindingContext, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return port.FindingContext{}, err
	}
	row, err := r.inner.GetFindingContext(ctx, fid)
	if err != nil {
		return port.FindingContext{}, mappingErr(err)
	}
	return port.FindingContext{
		EnvironmentID: toUUID(row.EnvironmentID),
		TargetID:      toUUID(row.TargetID),
		ArtifactID:    toUUID(row.ArtifactID),
	}, nil
}

func (r *pgFindingPort) GetFindingDisplayContext(ctx context.Context, findingID string) (port.FindingDisplayContext, error) {
	fid, err := parseID(findingID)
	if err != nil {
		return port.FindingDisplayContext{}, err
	}
	row, err := r.inner.GetFindingDisplayContext(ctx, fid)
	if err != nil {
		return port.FindingDisplayContext{}, mappingErr(err)
	}
	return port.FindingDisplayContext{
		FindingID:       findingID,
		TargetName:      strVal(row.TargetName),
		TargetKind:      strVal(row.TargetKind),
		TargetOwner:     strVal(row.TargetOwner),
		EnvironmentName: strVal(row.EnvironmentName),
		Branch:          strVal(row.Branch),
		CommitSha:       strVal(row.CommitSha),
		ToolName:        row.ToolName,
		LocationSummary: strVal(row.LocationSummary),
		Metadata:        append([]byte{}, row.Metadata...),
	}, nil
}

func (r *pgFindingPort) ListFindingDisplayContextsByIDs(ctx context.Context, findingIDs []string) ([]port.FindingDisplayContext, error) {
	uuids := make([]pgtype.UUID, 0, len(findingIDs))
	for _, id := range findingIDs {
		fid, err := parseID(id)
		if err != nil {
			return nil, err
		}
		uuids = append(uuids, fid)
	}
	rows, err := r.inner.ListFindingDisplayContextsByIDs(ctx, uuids)
	if err != nil {
		return nil, mappingErr(err)
	}
	out := make([]port.FindingDisplayContext, len(rows))
	for i, row := range rows {
		out[i] = port.FindingDisplayContext{
			FindingID:       toUUID(row.FindingID),
			TargetName:      strVal(row.TargetName),
			TargetKind:      strVal(row.TargetKind),
			TargetOwner:     strVal(row.TargetOwner),
			EnvironmentName: strVal(row.EnvironmentName),
			Branch:          strVal(row.Branch),
			CommitSha:       strVal(row.CommitSha),
			ToolName:        row.ToolName,
			LocationSummary: strVal(row.LocationSummary),
			Metadata:        append([]byte{}, row.Metadata...),
		}
	}
	return out, nil
}

func (r *pgFindingPort) ListBlockingFindings(ctx context.Context, projectID string, minSeverityRank int16) ([]port.Finding, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListBlockingFindings(ctx, pid, minSeverityRank)
	if err != nil {
		return nil, err
	}
	out := make([]port.Finding, len(rows))
	for i, row := range rows {
		out[i] = findingRowToPort(row)
	}
	return out, nil
}

func (r *pgFindingPort) FindScaFindingIDForPurlAndCve(ctx context.Context, projectID, purlName string, candidateIDs []string) (string, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return "", err
	}
	row, err := r.inner.FindScaFindingIdForPurlAndCve(ctx, pid, purlName, candidateIDs)
	if err != nil {
		return "", mappingErr(err)
	}
	return toUUID(row), nil
}

func (r *pgFindingPort) ListGateCandidates(ctx context.Context, projectID string, minSeverityRank int16) ([]port.GateCandidate, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.q.ListGateCandidates(ctx, sqlc.ListGateCandidatesParams{
		ProjectID:           pid,
		CurrentSeverityRank: minSeverityRank,
	})
	if err != nil {
		return nil, err
	}
	out := make([]port.GateCandidate, len(rows))
	for i, row := range rows {
		out[i] = port.GateCandidate{
			Finding: port.Finding{
				ID:                   toUUID(row.ID),
				ProjectID:            toUUID(row.ProjectID),
				FindingKind:          row.FindingKind,
				Fingerprint:          row.Fingerprint,
				CurrentTitle:         row.CurrentTitle,
				CurrentSeverityRank:  row.CurrentSeverityRank,
				AnalysisState:        row.AnalysisState,
				IntroducedByReportID: stringPtrFromUUID(row.IntroducedByReportID),
				IntroducedCommitSha:  stringFromTextPtr(row.IntroducedCommitSha),
			},
			Context: port.FindingContext{
				EnvironmentID: toUUID(row.EnvironmentID),
				TargetID:      toUUID(row.TargetID),
				ArtifactID:    toUUID(row.ArtifactID),
			},
			Reachability: string(row.ReachabilityState),
		}
	}
	return out, nil
}

func (r *pgFindingPort) ListIntroducedGateCandidates(ctx context.Context, reportID string, minSeverityRank int16) ([]port.GateCandidate, error) {
	rid, err := parseID(reportID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListIntroducedGateCandidates(ctx, rid, minSeverityRank)
	if err != nil {
		return nil, err
	}
	out := make([]port.GateCandidate, len(rows))
	for i, row := range rows {
		out[i] = port.GateCandidate{
			Finding: port.Finding{
				ID:                   toUUID(row.ID),
				ProjectID:            toUUID(row.ProjectID),
				FindingKind:          row.FindingKind,
				Fingerprint:          row.Fingerprint,
				CurrentTitle:         row.CurrentTitle,
				CurrentSeverityRank:  row.CurrentSeverityRank,
				AnalysisState:        row.AnalysisState,
				IntroducedByReportID: stringPtrFromUUID(row.IntroducedByReportID),
				IntroducedCommitSha:  stringFromTextPtr(row.IntroducedCommitSha),
			},
			Context: port.FindingContext{
				EnvironmentID: toUUID(row.EnvironmentID),
				TargetID:      toUUID(row.TargetID),
				ArtifactID:    toUUID(row.ArtifactID),
			},
			Reachability: string(row.ReachabilityState),
		}
	}
	return out, nil
}

func (r *pgFindingPort) ListFindingsByFingerprints(ctx context.Context, projectID, findingKind string, fingerprints []string) ([]port.Finding, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListFindingsByFingerprints(ctx, pid, findingKind, fingerprints)
	if err != nil {
		return nil, err
	}
	out := make([]port.Finding, len(rows))
	for i, row := range rows {
		out[i] = findingRowToPort(row)
	}
	return out, nil
}

func (r *pgFindingPort) ListFindingIDsPresentInReport(ctx context.Context, reportID string, findingIDs []string) ([]string, error) {
	rid, err := parseID(reportID)
	if err != nil {
		return nil, err
	}
	if len(findingIDs) == 0 {
		return nil, nil
	}
	uuids := make([]pgtype.UUID, 0, len(findingIDs))
	for _, id := range findingIDs {
		u, err := parseID(id)
		if err != nil {
			return nil, err
		}
		uuids = append(uuids, u)
	}
	rows, err := r.inner.ListFindingIDsPresentInReport(ctx, rid, uuids)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(rows))
	for i, row := range rows {
		out[i] = toUUID(row)
	}
	return out, nil
}

func (r *pgFindingPort) RecordReportIntroducedFindings(ctx context.Context, reportID string, baselineReportID *string, entries []port.IntroducedFindingEntry) error {
	rid, err := parseID(reportID)
	if err != nil {
		return err
	}
	var baseUUID pgtype.UUID
	if baselineReportID != nil && *baselineReportID != "" {
		b, err := parseID(*baselineReportID)
		if err != nil {
			return err
		}
		baseUUID = b
	}
	if len(entries) == 0 {
		return nil
	}
	findingIDs := make([]pgtype.UUID, 0, len(entries))
	changeTypes := make([]string, 0, len(entries))
	for _, e := range entries {
		fid, err := parseID(e.FindingID)
		if err != nil {
			return err
		}
		findingIDs = append(findingIDs, fid)
		changeTypes = append(changeTypes, e.ChangeType)
	}
	return r.inner.RecordReportIntroducedFindings(ctx, rid, baseUUID, findingIDs, changeTypes)
}

func (r *pgFindingPort) ListFindingsIntroducedByCommit(ctx context.Context, projectID, commitSha string) ([]port.Finding, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListFindingsIntroducedByCommit(ctx, pid, textPtrFromString(&commitSha))
	if err != nil {
		return nil, err
	}
	out := make([]port.Finding, len(rows))
	for i, row := range rows {
		out[i] = findingRowToPort(row)
	}
	return out, nil
}

func (r *pgFindingPort) PersistWatcherFinding(ctx context.Context, input port.PersistWatcherFindingInput) (port.Finding, error) {
	pid, err := parseID(input.Finding.ProjectID)
	if err != nil {
		return port.Finding{}, err
	}

	// Finding ids do not exist yet: the repo layer assigns them to the
	// dimensions, occurrence, and event after the finding row is inserted,
	// so any caller-supplied ids on this path are ignored (the watcher
	// create path carries none — empty is the normal shape).
	dimensions := make([]sqlc.UpsertDimensionParams, 0, len(input.Dimensions))
	for _, d := range input.Dimensions {
		dimensions = append(dimensions, sqlc.UpsertDimensionParams{
			DimKey:   d.Key,
			DimValue: d.Value,
			Source:   textPtrFromString(d.Source),
		})
	}

	occ := sqlc.CreateOccurrenceParams{
		Title:           input.Occurrence.Title,
		Description:     textPtrFromString(input.Occurrence.Description),
		Severity:        input.Occurrence.Severity,
		SeverityRank:    input.Occurrence.SeverityRank,
		Score:           floatToNumeric(input.Occurrence.Score),
		ToolName:        input.Occurrence.ToolName,
		ToolVersion:     textPtrFromString(input.Occurrence.ToolVersion),
		ParserVersion:   textPtrFromString(input.Occurrence.ParserVersion),
		LocationSummary: textPtrFromString(input.Occurrence.LocationSummary),
		SubjectSummary:  textPtrFromString(input.Occurrence.SubjectSummary),
		Remediation:     textPtrFromString(input.Occurrence.Remediation),
		Display:         input.Occurrence.Display,
		Metadata:        input.Occurrence.Metadata,
		ObservedAt:      uuidFromTime(input.Occurrence.ObservedAt),
	}

	var event *sqlc.CreateFindingEventParams
	if input.Event != nil {
		// The finding id only exists after the row is inserted — the repo
		// layer assigns it inside the transaction. Parse only when the
		// caller actually supplied one; an empty id is the watcher create
		// path's normal shape.
		var eventFindingID pgtype.UUID
		if input.Event.FindingID != "" {
			eventFindingID, err = parseID(input.Event.FindingID)
			if err != nil {
				return port.Finding{}, err
			}
		}
		event = &sqlc.CreateFindingEventParams{
			FindingID: eventFindingID,
			UserID:    uuidPtrFromString(input.Event.UserID),
			EventType: input.Event.EventType,
			OldValue:  textPtrFromString(input.Event.OldValue),
			NewValue:  textPtrFromString(input.Event.NewValue),
			Comment:   textPtrFromString(input.Event.Comment),
			Changes:   input.Event.Changes,
		}
	}

	var evidence *sqlc.CreateEvidenceParams
	if input.Evidence != nil {
		evidence = &sqlc.CreateEvidenceParams{
			Type:        input.Evidence.Type,
			Url:         input.Evidence.URL,
			Description: input.Evidence.Description,
		}
	}

	f, created, err := r.inner.PersistWatcherFinding(ctx, PersistWatcherFindingParams{
		Finding: sqlc.CreateFindingIfAbsentParams{
			ProjectID:           pid,
			FindingKind:         input.Finding.FindingKind,
			Fingerprint:         input.Finding.Fingerprint,
			CurrentTitle:        input.Finding.CurrentTitle,
			CurrentSeverity:     input.Finding.CurrentSeverity,
			CurrentSeverityRank: input.Finding.CurrentSeverityRank,
			CurrentScore:        floatToNumeric(findingScore(input.Finding)),
		},
		Dimensions: dimensions,
		Occurrence: occ,
		Event:      event,
		Evidence:   evidence,
	})
	if err != nil {
		return port.Finding{}, err
	}
	if !created {
		return port.Finding{}, port.ErrFindingSuppressed
	}
	return findingRowToPort(f), nil
}

func (r *pgFindingPort) CreateOccurrenceParamsFromInput(input port.OccurrenceInput) (CreateOccurrenceParams, error) {
	fid, err := parseID(input.FindingID)
	if err != nil {
		return CreateOccurrenceParams{}, err
	}
	var rid pgtype.UUID
	if input.ReportID != nil {
		parsed, err := parseID(*input.ReportID)
		if err != nil {
			return CreateOccurrenceParams{}, err
		}
		rid = parsed
	}
	return CreateOccurrenceParams{
		FindingID:       fid,
		ReportID:        rid,
		Title:           input.Title,
		Description:     textPtrFromString(input.Description),
		Severity:        input.Severity,
		SeverityRank:    input.SeverityRank,
		Score:           floatToNumeric(input.Score),
		ToolName:        input.ToolName,
		ToolVersion:     textPtrFromString(input.ToolVersion),
		ParserVersion:   textPtrFromString(input.ParserVersion),
		LocationSummary: textPtrFromString(input.LocationSummary),
		Display:         input.Display,
		Metadata:        input.Metadata,
	}, nil
}

func (r *pgFindingPort) PersistWatcherSkipEvent(ctx context.Context, findingID string, event port.FindingEventInput) error {
	fid, err := parseID(findingID)
	if err != nil {
		return err
	}
	ev := sqlc.CreateFindingEventParams{
		FindingID: fid,
		UserID:    uuidPtrFromString(event.UserID),
		EventType: event.EventType,
		OldValue:  textPtrFromString(event.OldValue),
		NewValue:  textPtrFromString(event.NewValue),
		Comment:   textPtrFromString(event.Comment),
		Changes:   event.Changes,
	}
	return r.inner.PersistWatcherSkipEvent(ctx, ev)
}

// CreateOccurrenceParamsFromInput maps a port occurrence to repo params.

func findingScore(f port.Finding) float64 {
	if f.CurrentScore != nil {
		return *f.CurrentScore
	}
	return 0
}

func floatToNumeric(s float64) pgtype.Numeric {
	if s <= 0 {
		return pgtype.Numeric{Valid: false}
	}
	return pgtype.Numeric{Int: big.NewInt(int64(s * 10)), Exp: -1, Valid: true}
}

func floatPtrFromNumeric(n pgtype.Numeric) *float64 {
	if !n.Valid {
		return nil
	}
	f, err := n.Float64Value()
	if err != nil || !f.Valid {
		return nil
	}
	v := f.Float64
	return &v
}

func reportRowToPort(re sqlc.Report) port.Report {
	return port.Report{
		ID:            toUUID(re.ID),
		ProjectID:     toUUID(re.ProjectID),
		ToolName:      re.ToolName,
		ToolVersion:   stringFromTextPtr(re.ToolVersion),
		ScanType:      re.ScanType,
		ScanTarget:    stringFromTextPtr(re.ScanTarget),
		Status:        re.Status,
		TotalFindings: int32PtrFromInt4(re.TotalFindings),
		Branch:        stringFromTextPtr(re.Branch),
		CommitSha:     stringFromTextPtr(re.CommitSha),
		BaseRevision:  stringFromTextPtr(re.BaseRevision),
		ChangedFiles:  changedFilesToPort(re.ChangedFiles),
		ScanMode:      re.ScanMode,
		ErrorMessage:  stringFromTextPtr(re.ErrorMessage),
		CreatedAt:     re.CreatedAt.Time,
		CompletedAt:   timePtrFromTimestamptz(re.CompletedAt),
	}
}

// changedFilesToPort decodes the JSONB path list; nil/empty decodes as nil
// so callers treat "no recorded files" and "empty list" identically.
func changedFilesToPort(raw []byte) json.RawMessage {
	if len(raw) == 0 {
		return nil
	}
	out := make([]byte, len(raw))
	copy(out, raw)
	return json.RawMessage(out)
}

func int32PtrFromInt4(i pgtype.Int4) *int32 {
	if !i.Valid {
		return nil
	}
	v := i.Int32
	return &v
}

func findingRowToPort(f sqlc.Finding) port.Finding {
	return port.Finding{
		ID:                   toUUID(f.ID),
		ProjectID:            toUUID(f.ProjectID),
		FindingKind:          f.FindingKind,
		Fingerprint:          f.Fingerprint,
		CurrentTitle:         f.CurrentTitle,
		CurrentSeverity:      f.CurrentSeverity,
		CurrentSeverityRank:  f.CurrentSeverityRank,
		CurrentScore:         floatPtrFromNumeric(f.CurrentScore),
		State:                f.State,
		TriageStatus:         f.TriageStatus,
		AnalysisState:        f.AnalysisState,
		GateEffect:           f.GateEffect,
		AnalysisExpiresAt:    timePtrFromTimestamptz(f.AnalysisExpiresAt),
		AnalysisReason:       stringFromTextPtr(f.AnalysisReason),
		AnalysisSource:       f.AnalysisSource,
		ManualOverride:       f.ManualOverride,
		ReviewRequired:       f.ReviewRequired,
		FingerprintVersion:   f.FingerprintVersion,
		FirstSeenAt:          f.FirstSeenAt.Time,
		LastSeenAt:           f.LastSeenAt.Time,
		CreatedAt:            f.CreatedAt.Time,
		UpdatedAt:            f.UpdatedAt.Time,
		IntroducedByReportID: stringPtrFromUUID(f.IntroducedByReportID),
		IntroducedCommitSha:  stringFromTextPtr(f.IntroducedCommitSha),
	}
}

func findingEventRowToPort(e sqlc.FindingEvent) port.FindingEvent {
	return port.FindingEvent{
		ID:        toUUID(e.ID),
		FindingID: toUUID(e.FindingID),
		UserID:    stringPtrFromUUID(e.UserID),
		EventType: e.EventType,
		OldValue:  stringFromTextPtr(e.OldValue),
		NewValue:  stringFromTextPtr(e.NewValue),
		Comment:   stringFromTextPtr(e.Comment),
		Changes:   e.Changes,
		CreatedAt: e.CreatedAt.Time,
	}
}

func uuidFromString(s string) pgtype.UUID {
	u, err := uuid.Parse(s)
	if err != nil {
		return pgtype.UUID{Valid: false}
	}
	return pgtype.UUID{Bytes: u, Valid: true}
}
