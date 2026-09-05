package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/db/sqlc"
	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/finding"
	"github.com/xMinhx/specht/internal/repo"
	"github.com/xMinhx/specht/internal/scanner"
)

// reportContext carries the contextual rows resolved for an ingested report:
// the (optional) target/artifact/environment ids and the target identifier
// used to derive the scan-scope hash.
type reportContext struct {
	targetID         pgtype.UUID
	artifactID       pgtype.UUID
	environmentID    pgtype.UUID
	targetIdentifier string
}

func (u *Usecases) IngestReport(ctx context.Context, input IngestReportInput) (*IngestReportOutput, error) {
	if input.ProjectSlug == "" {
		return nil, fmt.Errorf("project slug is required")
	}
	if input.Scanner == "" {
		return nil, fmt.Errorf("scanner name is required")
	}
	if len(input.RawData) == 0 {
		return nil, fmt.Errorf("raw scan data is required")
	}

	project, err := u.deps.Repos.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", input.ProjectSlug, err)
	}

	sc, err := u.deps.Registry.Get(input.Scanner)
	if err != nil {
		return nil, fmt.Errorf("unknown scanner %q", input.Scanner)
	}

	nr, err := sc.Parse(ctx, input.RawData)
	if err != nil {
		slog.Error("scanner parse failed", "scanner", input.Scanner, "error", err)
		return nil, fmt.Errorf("scanner %s: parse output: %w", input.Scanner, err)
	}

	ctxInfo, err := u.resolveReportContext(ctx, project, input, nr)
	if err != nil {
		return nil, err
	}

	report, err := u.createReport(ctx, project, input, nr, ctxInfo)
	if err != nil {
		return nil, err
	}

	total, err := u.ingestReportFindings(ctx, project, input, report, nr)
	if err != nil {
		return nil, err
	}

	if err := u.persistInventory(ctx, input, report, nr); err != nil {
		return nil, err
	}

	thresholdBreached, err := u.checkGateAfterIngest(ctx, project, input, report, total)
	if err != nil {
		return nil, err
	}

	return &IngestReportOutput{
		ReportID:          uuid.UUID(report.ID.Bytes).String(),
		TotalFindings:     total,
		ThresholdBreached: thresholdBreached,
	}, nil
}

// resolveReportContext upserts the target/artifact/environment rows a report
// references (best-effort: a failure to resolve context does not fail the
// ingest) and returns their ids plus the target identifier for the scope
// hash. The sqlc rows carry pgtype.UUID zero values when absent.
func (u *Usecases) resolveReportContext(ctx context.Context, project sqlc.Project, input IngestReportInput, nr *scanner.NormalizedReport) (reportContext, error) {
	var out reportContext

	if nr.Target != nil && nr.Target.Identifier != "" {
		out.targetIdentifier = nr.Target.Identifier
		kind := nr.Target.Kind
		if kind == "" {
			kind = string(nr.ScanType)
		}
		t, err := u.deps.Repos.Targets.Upsert(ctx, sqlc.UpsertTargetParams{
			ProjectID: project.ID,
			Name:      nr.Target.Identifier,
			Kind:      kind,
			Locator:   pgtype.Text{String: nr.Target.Identifier, Valid: true},
		})
		if err != nil {
			slog.Warn("upsert target failed", "project", project.ID, "target", nr.Target.Identifier, "error", err)
		} else {
			out.targetID = t.ID
		}
	}

	artifactName := input.ArtifactName
	if artifactName == "" && nr.Artifact != nil {
		artifactName = nr.Artifact.Identifier
	}
	if artifactName != "" {
		artifactType := input.ArtifactType
		if artifactType == "" && nr.Artifact != nil {
			artifactType = nr.Artifact.Kind
		}
		if artifactType == "" {
			artifactType = string(nr.ScanType)
		}
		metadata := []byte("{}")
		if nr.Artifact != nil {
			metadata = mustMarshal(nr.Artifact.Metadata)
			if metadata == nil {
				metadata = []byte("{}")
			}
		}
		a, err := u.deps.Repos.Artifacts.Upsert(ctx, sqlc.UpsertArtifactParams{
			ProjectID:    project.ID,
			TargetID:     out.targetID,
			ArtifactType: artifactType,
			Name:         artifactName,
			Version:      textPtr(input.ArtifactVersion),
			Digest:       pgtype.Text{Valid: false},
			Locator:      pgtype.Text{Valid: false},
			Metadata:     metadata,
		})
		if err != nil {
			slog.Warn("upsert artifact failed", "project", project.ID, "artifact", artifactName, "error", err)
		} else {
			out.artifactID = a.ID
		}
	}

	if input.Environment != "" {
		e, err := u.deps.Repos.Environments.Upsert(ctx, sqlc.UpsertEnvironmentParams{
			ProjectID:       project.ID,
			Name:            input.Environment,
			Tier:            "development",
			InternetFacing:  false,
			DataSensitivity: "internal",
		})
		if err != nil {
			slog.Warn("upsert environment failed", "project", project.ID, "environment", input.Environment, "error", err)
		} else {
			out.environmentID = e.ID
		}
	}

	return out, nil
}

// createReport persists the report row, returning ErrDuplicateReport on a
// raw-data hash collision.
func (u *Usecases) createReport(ctx context.Context, project sqlc.Project, input IngestReportInput, nr *scanner.NormalizedReport, ctxInfo reportContext) (sqlc.Report, error) {
	rawHash := sha256.Sum256(input.RawData)
	scopeHash := sha256.Sum256([]byte(input.Scanner + ":" + ctxInfo.targetIdentifier))

	report, err := u.deps.Repos.Reports.Create(ctx, repo.CreateReportParams{
		ProjectID:     project.ID,
		ToolName:      input.Scanner,
		ToolVersion:   textPtr(input.ScannerVersion),
		ScanType:      string(nr.ScanType),
		ScanTarget:    textPtr(nr.Target.Identifier),
		TargetID:      ctxInfo.targetID,
		ArtifactID:    ctxInfo.artifactID,
		EnvironmentID: ctxInfo.environmentID,
		ScanScope:     mustMarshal(nr.ScanScope),
		ScanScopeHash: pgtype.Text{String: hex.EncodeToString(scopeHash[:]), Valid: true},
		Branch:        textPtr(input.Branch),
		CommitSha:     textPtr(input.CommitSha),
		RawData:       input.RawData,
		RawReportHash: pgtype.Text{String: hex.EncodeToString(rawHash[:]), Valid: true},
		ParserVersion: textPtr(input.ParserVersion),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return sqlc.Report{}, ErrDuplicateReport
		}
		slog.Error("create report failed", "scanner", input.Scanner, "error", err)
		return sqlc.Report{}, fmt.Errorf("scanner %s: create report: %w", input.Scanner, err)
	}
	return report, nil
}

// ingestReportFindings upserts each normalized finding and its occurrence,
// dimensions, and material-change events. It returns the number of findings
// ingested.
func (u *Usecases) ingestReportFindings(ctx context.Context, project sqlc.Project, input IngestReportInput, report sqlc.Report, nr *scanner.NormalizedReport) (int, error) {
	nowTime := now()
	total := 0

	for _, f := range nr.Findings {
		ingested, err := u.ingestOneFinding(ctx, project, input, report, f, nowTime)
		if err != nil {
			return 0, err
		}
		total += ingested
	}
	return total, nil
}

func (u *Usecases) ingestOneFinding(ctx context.Context, project sqlc.Project, input IngestReportInput, report sqlc.Report, f scanner.NormalizedFinding, nowTime pgtype.Timestamptz) (int, error) {
	newRank := severityRank(f.Severity)

	var oldRank int16
	var oldGateEffect string
	var oldAnalysisState string

	existing, lookupErr := u.deps.Repos.Findings.GetByFingerprint(ctx, repo.GetByFingerprintParams{
		ProjectID:   project.ID,
		FindingKind: f.FindingKind,
		Fingerprint: f.Fingerprint,
	})
	// A lookup error (incl. pgx.ErrNoRows) means there is no existing
	// finding yet; only carry forward gate state when one exists.
	if lookupErr == nil {
		oldRank = existing.CurrentSeverityRank
		oldGateEffect = existing.GateEffect
		oldAnalysisState = existing.AnalysisState
	}

	upserted, err := u.deps.Repos.Findings.Upsert(ctx, repo.UpsertFindingParams{
		ProjectID:    project.ID,
		FindingKind:  f.FindingKind,
		Fingerprint:  f.Fingerprint,
		CurrentTitle: f.Title,
		Severity:     severityStr(f.Severity),
		SeverityRank: newRank,
		Score:        scoreToNumeric(f.Score),
		FirstSeenAt:  nowTime,
		LastSeenAt:   nowTime,
	})
	if err != nil {
		slog.Error("upsert finding failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
		return 0, fmt.Errorf("scanner %s: upsert finding %q: %w", input.Scanner, f.Fingerprint, err)
	}

	_, err = u.deps.Repos.Findings.CreateOccurrence(ctx, repo.CreateOccurrenceParams{
		FindingID:       upserted.ID,
		ReportID:        report.ID,
		Title:           f.Title,
		Description:     textPtr(f.Description),
		Severity:        severityStr(f.Severity),
		SeverityRank:    severityRank(f.Severity),
		Score:           scoreToNumeric(f.Score),
		ToolName:        input.Scanner,
		ToolVersion:     textPtr(input.ScannerVersion),
		ParserVersion:   textPtr(input.ParserVersion),
		LocationSummary: textPtr(f.Location),
		Display:         mustMarshal(f.Display),
		Metadata:        mustMarshal(f.Metadata),
	})
	if err != nil {
		slog.Error("create occurrence failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
		return 0, fmt.Errorf("scanner %s: create occurrence for %q: %w", input.Scanner, f.Fingerprint, err)
	}

	for _, d := range f.Dimensions {
		_, err = u.deps.Repos.Findings.UpsertDimension(ctx, repo.UpsertDimensionParams{
			FindingID: upserted.ID,
			Key:       d.Key,
			Value:     d.Value,
			Source:    pgtype.Text{String: input.Scanner, Valid: true},
		})
		if err != nil {
			slog.Error("upsert dimension failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
			return 0, fmt.Errorf("scanner %s: upsert dimension for %q: %w", input.Scanner, f.Fingerprint, err)
		}
	}

	if lookupErr == nil && (oldAnalysisState != string(finding.StateUnanalyzed) || oldGateEffect == string(finding.EffectIgnore)) {
		if err := u.applyMaterialChange(ctx, project, input, upserted, f, oldRank, oldGateEffect, oldAnalysisState); err != nil {
			return 0, err
		}
	}

	return 1, nil
}

// applyMaterialChange runs finding.EvaluateChange on a previously-known
// finding and, when the change demands review, marks review_required and logs
// the material-change event.
func (u *Usecases) applyMaterialChange(ctx context.Context, project sqlc.Project, input IngestReportInput, upserted sqlc.Finding, f scanner.NormalizedFinding, oldRank int16, oldGateEffect, oldAnalysisState string) error {
	hasNewFix := false
	for _, d := range f.Dimensions {
		if d.Key == domain.DimFixedVersion && d.Value != "" {
			hasNewFix = true
			break
		}
	}

	var hadOldFix bool
	if hasNewFix {
		hadOldFix, _ = u.deps.Repos.Findings.HasDimension(ctx, upserted.ID, domain.DimFixedVersion)
	}

	change := finding.EvaluateChange(finding.PreviousFinding{
		SeverityRank:  oldRank,
		GateEffect:    finding.GateEffect(oldGateEffect),
		Analysis:      finding.AnalysisState(oldAnalysisState),
		HadFixVersion: hadOldFix,
	}, finding.CurrentFinding{
		SeverityRank: severityRank(f.Severity),
		HasNewFix:    hasNewFix,
	})

	if change == nil || !change.ReviewRequired {
		return nil
	}

	_, err := u.deps.Repos.Findings.UpdateAnalysis(ctx, repo.UpdateAnalysisParams{
		ID:             upserted.ID,
		AnalysisState:  upserted.AnalysisState,
		GateEffect:     upserted.GateEffect,
		AnalysisSource: upserted.AnalysisSource,
		ReviewRequired: true,
	})
	if err != nil {
		slog.Error("set review_required failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
		return fmt.Errorf("scanner %s: set review_required for finding %q: %w", input.Scanner, f.Fingerprint, err)
	}

	changesJSON, _ := json.Marshal(change.Changes)
	_, err = u.deps.Repos.Findings.CreateEvent(ctx, repo.CreateEventParams{
		FindingID: upserted.ID,
		EventType: change.EventType,
		Changes:   changesJSON,
	})
	if err != nil {
		slog.Error("log material change event failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
		return fmt.Errorf("scanner %s: log material change event: %w", input.Scanner, err)
	}
	return nil
}

// persistInventory writes the report's package references when any exist.
func (u *Usecases) persistInventory(ctx context.Context, input IngestReportInput, report sqlc.Report, nr *scanner.NormalizedReport) error {
	if len(nr.Packages) == 0 {
		return nil
	}
	if err := u.deps.Repos.Inventory.UpsertReportPackages(ctx, report.ID, toInventoryPackageParams(nr.Packages)); err != nil {
		slog.Error("persist package inventory failed", "scanner", input.Scanner, "report_id", report.ID, "error", err)
		return fmt.Errorf("scanner %s: persist package inventory: %w", input.Scanner, err)
	}
	return nil
}

// checkGateAfterIngest marks the report completed and reports whether any
// blocking finding exists at the configured severity/status threshold.
func (u *Usecases) checkGateAfterIngest(ctx context.Context, project sqlc.Project, input IngestReportInput, report sqlc.Report, total int) (bool, error) {
	_, err := u.deps.Repos.Reports.UpdateStatus(ctx, report.ID, project.ID, "completed", total, pgtype.Text{Valid: false})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return false, ErrDuplicateReport
		}
		slog.Error("update report status failed", "scanner", input.Scanner, "report_id", report.ID, "error", err)
		return false, fmt.Errorf("scanner %s: update report status: %w", input.Scanner, err)
	}

	severities, statuses := defaultGateParams(input.GateSeverity, input.GateStatus)
	gateFindings, err := u.deps.Repos.Findings.ListByProject(ctx, project.ID, severities, statuses, nil, 1, 0)
	if err != nil {
		slog.Error("gate check failed", "scanner", input.Scanner, "project", project.ID, "error", err)
		return false, fmt.Errorf("scanner %s: gate check: %w", input.Scanner, err)
	}
	return len(gateFindings) > 0, nil
}
