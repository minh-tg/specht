package repo

import (
	"context"
	"errors"
	"math/big"
	"time"

	"github.com/google/uuid"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/port"
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
	status := input.Status
	if status == "" {
		status = "processing"
	}
	row, err := r.inner.Create(ctx, CreateReportParams{
		ProjectID:     pid,
		ToolName:      input.ToolName,
		ToolVersion:   textPtrFromString(input.ToolVersion),
		ScanType:      input.ScanType,
		ScanTarget:    textPtrFromString(input.ScanTarget),
		TargetID:      uuidPtrFromString(&input.TargetID),
		ArtifactID:    uuidPtrFromString(&input.ArtifactID),
		EnvironmentID: uuidPtrFromString(&input.EnvironmentID),
		ScanScope:     input.ScanScope,
		ScanScopeHash: textPtrFromString(&input.ScanScopeHash),
		Branch:        textPtrFromString(input.Branch),
		CommitSha:     textPtrFromString(input.CommitSha),
		RawData:       input.RawData,
		RawReportHash: textPtrFromString(&input.RawReportHash),
		ParserVersion: textPtrFromString(input.ParserVersion),
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
		return port.Report{}, err
	}
	return reportRowToPort(row), nil
}

// ---------- Findings port over the existing repo methods ----------

type pgFindingPort struct{ inner *pgFindingRepo }

func newFindingPort(r *pgFindingRepo) *pgFindingPort { return &pgFindingPort{inner: r} }

func (r *pgFindingPort) Upsert(ctx context.Context, projectID, findingKind, fingerprint, title, severity string, severityRank int16, score float64, firstSeen, lastSeen time.Time) (port.Finding, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return port.Finding{}, err
	}
	row, err := r.inner.Upsert(ctx, UpsertFindingParams{
		ProjectID:    pid,
		FindingKind:  findingKind,
		Fingerprint:  fingerprint,
		CurrentTitle: title,
		Severity:     severity,
		SeverityRank: severityRank,
		Score:        floatToNumeric(score),
		FirstSeenAt:  uuidFromTime(firstSeen),
		LastSeenAt:   uuidFromTime(lastSeen),
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

func (r *pgFindingPort) ListByProject(ctx context.Context, projectID string, severities, states, kinds []string, limit, offset int32) ([]port.Finding, error) {
	pid, err := parseID(projectID)
	if err != nil {
		return nil, err
	}
	rows, err := r.inner.ListByProject(ctx, pid, severities, states, kinds, limit, offset)
	if err != nil {
		return nil, err
	}
	out := make([]port.Finding, len(rows))
	for i, row := range rows {
		out[i] = findingRowToPort(row)
	}
	return out, nil
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
				ID:                  toUUID(row.ID),
				ProjectID:           toUUID(row.ProjectID),
				FindingKind:         row.FindingKind,
				Fingerprint:         row.Fingerprint,
				CurrentTitle:        row.CurrentTitle,
				CurrentSeverityRank: row.CurrentSeverityRank,
				AnalysisState:       row.AnalysisState,
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

func (r *pgFindingPort) PersistWatcherFinding(ctx context.Context, input port.PersistWatcherFindingInput) (port.Finding, error) {
	pid, err := parseID(input.Finding.ProjectID)
	if err != nil {
		return port.Finding{}, err
	}

	dimensions := make([]sqlc.UpsertDimensionParams, 0, len(input.Dimensions))
	for _, d := range input.Dimensions {
		fid, err := parseID(d.FindingID)
		if err != nil {
			return port.Finding{}, err
		}
		dimensions = append(dimensions, sqlc.UpsertDimensionParams{
			FindingID: fid,
			DimKey:    d.Key,
			DimValue:  d.Value,
			Source:    textPtrFromString(d.Source),
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
		fid, err := parseID(input.Event.FindingID)
		if err != nil {
			return port.Finding{}, err
		}
		event = &sqlc.CreateFindingEventParams{
			FindingID: fid,
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
		CreatedAt:     re.CreatedAt.Time,
		CompletedAt:   timePtrFromTimestamptz(re.CompletedAt),
	}
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
		ID:                  toUUID(f.ID),
		ProjectID:           toUUID(f.ProjectID),
		FindingKind:         f.FindingKind,
		Fingerprint:         f.Fingerprint,
		CurrentTitle:        f.CurrentTitle,
		CurrentSeverity:     f.CurrentSeverity,
		CurrentSeverityRank: f.CurrentSeverityRank,
		CurrentScore:        floatPtrFromNumeric(f.CurrentScore),
		State:               f.State,
		TriageStatus:        f.TriageStatus,
		AnalysisState:       f.AnalysisState,
		GateEffect:          f.GateEffect,
		AnalysisExpiresAt:   timePtrFromTimestamptz(f.AnalysisExpiresAt),
		AnalysisReason:      stringFromTextPtr(f.AnalysisReason),
		AnalysisSource:      f.AnalysisSource,
		ManualOverride:      f.ManualOverride,
		ReviewRequired:      f.ReviewRequired,
		FingerprintVersion:  f.FingerprintVersion,
		FirstSeenAt:         f.FirstSeenAt.Time,
		LastSeenAt:          f.LastSeenAt.Time,
		CreatedAt:           f.CreatedAt.Time,
		UpdatedAt:           f.UpdatedAt.Time,
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
