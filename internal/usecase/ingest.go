package usecase

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/xMinhx/specht/internal/domain"
	"github.com/xMinhx/specht/internal/finding"
	"github.com/xMinhx/specht/internal/gate"
	"github.com/xMinhx/specht/internal/port"
	"github.com/xMinhx/specht/internal/scanner"
	"github.com/xMinhx/specht/internal/tracker"
)

// Scan modes for report ingestion.
const (
	// ScanModeFull is a complete scan: absence of a finding verifies a fix.
	ScanModeFull = "full"
	// ScanModeIncremental covers only changed files: absence proves
	// nothing, so nothing is ever marked fixed from an incremental scan.
	ScanModeIncremental = "incremental"
)

// normalizeScanMode defaults an empty mode to full and rejects anything
// outside the full/incremental vocabulary.
func normalizeScanMode(mode string) (string, error) {
	normalized := strings.ToLower(strings.TrimSpace(mode))
	if normalized == "" {
		return ScanModeFull, nil
	}
	if normalized != ScanModeFull && normalized != ScanModeIncremental {
		return "", fmt.Errorf("invalid scan_mode %q: must be %q or %q", mode, ScanModeFull, ScanModeIncremental)
	}
	return normalized, nil
}

// reportContext carries the contextual ids resolved for an ingested report
// and the target identifier used to derive the scan-scope hash.
type reportContext struct {
	targetID         string
	artifactID       string
	environmentID    string
	targetIdentifier string
}

// redactRaw lets a scanner scrub sensitive material from raw evidence
// before it is hashed and stored. Scanners opt in by implementing
// RedactRaw; all other scanners store bytes verbatim.
func redactRaw(sc scanner.Scanner, raw []byte) []byte {
	if r, ok := sc.(interface{ RedactRaw([]byte) []byte }); ok {
		return r.RedactRaw(raw)
	}
	return raw
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
	scanMode, err := normalizeScanMode(input.ScanMode)
	if err != nil {
		return nil, err
	}
	input.ScanMode = scanMode
	if scanMode == ScanModeIncremental && strings.TrimSpace(input.BaseRevision) == "" {
		return nil, fmt.Errorf("incremental scan requires base_revision")
	}

	project, err := u.deps.Stores.Projects.GetBySlug(ctx, input.ProjectSlug)
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
	input.RawData = redactRaw(sc, input.RawData)

	ctxInfo, err := u.resolveReportContext(ctx, project, input, nr)
	if err != nil {
		return nil, err
	}

	// Incremental scans (SOLO-165) resolve an effective mode before any
	// row is written: unsupported scanners and missing baselines fall
	// back to full with an explicit reason instead of recording partial
	// coverage as if it were complete.
	effectiveMode, fallbackReason, baselineID, err := u.resolveScanMode(ctx, project, sc, input)
	if err != nil {
		return nil, err
	}
	input.ScanMode = effectiveMode

	report, err := u.createReport(ctx, project, input, nr, ctxInfo)
	if err != nil {
		return nil, err
	}

	outcome, err := u.ingestReportFindings(ctx, project, input, report, nr, baselineID)
	if err != nil {
		u.markReportFailed(ctx, input, report, err)
		return nil, err
	}

	if err := u.persistInventory(ctx, input, report, nr); err != nil {
		u.markReportFailed(ctx, input, report, err)
		return nil, err
	}

	thresholdBreached, err := u.checkGateAfterIngest(ctx, project, input, report, outcome.total)
	if err != nil {
		return nil, err
	}

	return &IngestReportOutput{
		ReportID:          report.ID,
		TotalFindings:     outcome.total,
		ThresholdBreached: thresholdBreached,
		ScanMode:          effectiveMode,
		FallbackReason:    fallbackReason,
		IntroducedCount:   outcome.introduced,
		PreExistingCount:  outcome.preExisting,
	}, nil
}

// resolveScanMode maps a requested scan mode to its effective mode. Full
// scans pass through; incremental scans require a scanner that opted into
// incremental analysis and a completed full baseline for the base revision.
// Anything else degrades to a full scan with an explicit reason — gates
// must never silently pass on omitted coverage.
func (u *Usecases) resolveScanMode(ctx context.Context, project port.Project, sc scanner.Scanner, input IngestReportInput) (string, string, string, error) {
	if input.ScanMode != ScanModeIncremental {
		return ScanModeFull, "", "", nil
	}
	if !scanner.SupportsIncremental(sc) {
		return ScanModeFull, fmt.Sprintf("scanner %q does not support incremental scans; recorded as full scan", input.Scanner), "", nil
	}
	base, err := u.deps.Stores.Reports.GetCompletedByCommit(ctx, project.ID, input.Scanner, input.BaseRevision)
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return ScanModeFull, fmt.Sprintf("no completed full baseline for base_revision %q; recorded as full scan", input.BaseRevision), "", nil
		}
		return "", "", "", fmt.Errorf("resolve incremental baseline: %w", err)
	}
	return ScanModeIncremental, "", base.ID, nil
}

// resolveReportContext upserts the target/artifact/environment rows a report
// references (best-effort: a failure to resolve context does not fail the
// ingest) and returns their ids plus the target identifier for the scope hash.
func (u *Usecases) resolveReportContext(ctx context.Context, project port.Project, input IngestReportInput, nr *domain.NormalizedReport) (reportContext, error) {
	var out reportContext

	if nr.Target != nil && nr.Target.Identifier != "" {
		out.targetIdentifier = nr.Target.Identifier
		kind := nr.Target.Kind
		if kind == "" {
			kind = string(nr.ScanType)
		}
		t, err := u.deps.Stores.Targets.Upsert(ctx, project.ID, nr.Target.Identifier, kind, nr.Target.Identifier, input.Owner)
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
		digest := input.Digest
		if digest == "" && nr.Artifact != nil {
			digest = nr.Artifact.Digest
		}
		a, err := u.deps.Stores.Artifacts.Upsert(ctx, port.ArtifactInput{
			ProjectID:    project.ID,
			TargetID:     out.targetID,
			ArtifactType: artifactType,
			Name:         artifactName,
			Version:      textPtr(input.ArtifactVersion),
			Digest:       textPtr(digest),
			Metadata:     metadata,
		})
		if err != nil {
			slog.Warn("upsert artifact failed", "project", project.ID, "artifact", artifactName, "error", err)
		} else {
			out.artifactID = a.ID
		}
	}

	if input.Environment != "" {
		e, err := u.deps.Stores.Environments.Upsert(ctx, project.ID, input.Environment, "development", false, "internal")
		if err != nil {
			slog.Warn("upsert environment failed", "project", project.ID, "environment", input.Environment, "error", err)
		} else {
			out.environmentID = e.ID
		}
	}

	return out, nil
}

// createReport persists the report row, returning ErrDuplicateReport on a
// raw-data hash collision. The scope hash is computed from the full typed
// scan scope (scanner, target, artifact, branch, commit SHA, environment)
// so identical content scanned at a different revision or artifact never
// collides.
func (u *Usecases) createReport(ctx context.Context, project port.Project, input IngestReportInput, nr *domain.NormalizedReport, ctxInfo reportContext) (port.Report, error) {
	rawHash := sha256.Sum256(input.RawData)
	scopeHash := sha256.Sum256([]byte(scopeHashMaterial(input, nr, ctxInfo)))

	scanTarget := ""
	if nr.Target != nil {
		scanTarget = nr.Target.Identifier
	}

	report, err := u.deps.Stores.Reports.Create(ctx, port.CreateReportInput{
		ProjectID:        project.ID,
		ToolName:         input.Scanner,
		ToolVersion:      textPtr(input.ScannerVersion),
		ScanType:         string(nr.ScanType),
		ScanTarget:       textPtr(scanTarget),
		TargetID:         ctxInfo.targetID,
		ArtifactID:       ctxInfo.artifactID,
		EnvironmentID:    ctxInfo.environmentID,
		ScanScope:        mustMarshal(scopeDocument(nr)),
		ScanScopeHash:    hex.EncodeToString(scopeHash[:]),
		Branch:           textPtr(input.Branch),
		CommitSha:        textPtr(input.CommitSha),
		BaseRevision:     textPtr(input.BaseRevision),
		ChangedFiles:     changedFilesDocument(input.ChangedFiles),
		ScanMode:         input.ScanMode,
		RawData:          input.RawData,
		RawReportHash:    hex.EncodeToString(rawHash[:]),
		ParserVersion:    textPtr(input.ParserVersion),
		ScanCompleteness: string(nr.Completeness),
		Status:           "processing",
	})
	if err != nil {
		if errors.Is(err, port.ErrDuplicateReport) {
			return port.Report{}, ErrDuplicateReport
		}
		slog.Error("create report failed", "scanner", input.Scanner, "error", err)
		return port.Report{}, fmt.Errorf("scanner %s: create report: %w", input.Scanner, err)
	}
	return report, nil
}

// changedFilesDocument encodes the covered-path list for storage. Empty
// encodes as nil (the store persists []), so full scans carry no list.
func changedFilesDocument(files []string) json.RawMessage {
	if len(files) == 0 {
		return nil
	}
	return mustMarshal(files)
}

// scopeHashMaterial is the deterministic, ordered material the scope hash is
// computed from: every attribute that distinguishes one scan scope from
// another.
func scopeHashMaterial(input IngestReportInput, nr *domain.NormalizedReport, ctxInfo reportContext) string {
	target := ""
	if nr.Target != nil {
		target = nr.Target.Identifier
	}
	return strings.Join([]string{
		input.Scanner,
		target,
		input.ArtifactName,
		input.ArtifactVersion,
		input.Branch,
		input.CommitSha,
		input.Environment,
	}, "\x00")
}

// scopeDocument renders the persisted scan_scope JSONB: the typed scope
// attributes plus transport-supplied extension attributes, in a stable
// shape.
func scopeDocument(nr *domain.NormalizedReport) map[string]any {
	doc := map[string]any{}
	if nr.ScanScope == nil {
		return doc
	}
	s := nr.ScanScope
	if s.Target != "" {
		doc["target"] = s.Target
	}
	if s.TargetKind != "" {
		doc["target_kind"] = s.TargetKind
	}
	if s.Artifact != "" {
		doc["artifact"] = s.Artifact
	}
	if s.ArtifactVer != "" {
		doc["artifact_version"] = s.ArtifactVer
	}
	if s.ArtifactTyp != "" {
		doc["artifact_type"] = s.ArtifactTyp
	}
	if s.Branch != "" {
		doc["branch"] = s.Branch
	}
	if s.CommitSha != "" {
		doc["commit_sha"] = s.CommitSha
	}
	if len(s.Ext) > 0 {
		ext := make(map[string]string, len(s.Ext))
		for k, v := range s.Ext {
			ext[k] = v
		}
		doc["ext"] = ext
	}
	return doc
}

// ingestOutcome tallies what one ingest observed: every finding ingested,
// split into introduced (new to the change or project) and pre-existing.
type ingestOutcome struct {
	total       int
	introduced  int
	preExisting int
}

// ingestReportFindings upserts each normalized finding and its occurrence,
// dimensions, and material-change events. baselineID is the incremental
// baseline report (empty for full scans); findings absent from it count as
// introduced, the rest as pre-existing.
func (u *Usecases) ingestReportFindings(ctx context.Context, project port.Project, input IngestReportInput, report port.Report, nr *domain.NormalizedReport, baselineID string) (ingestOutcome, error) {
	nowTime := now()
	var outcome ingestOutcome

	for _, f := range nr.Findings {
		ingested, introduced, err := u.ingestOneFinding(ctx, project, input, report, f, nowTime, baselineID)
		if err != nil {
			return ingestOutcome{}, err
		}
		outcome.total += ingested
		if ingested > 0 {
			if introduced {
				outcome.introduced++
			} else {
				outcome.preExisting++
			}
		}
	}
	return outcome, nil
}

func (u *Usecases) ingestOneFinding(ctx context.Context, project port.Project, input IngestReportInput, report port.Report, f domain.NormalizedFinding, nowTime time.Time, baselineID string) (ingested int, introduced bool, err error) {
	newRank := severityRank(f.Severity)

	var oldRank int16
	var oldGateEffect string
	var oldAnalysisState string

	existing, lookupErr := u.deps.Stores.Findings.GetByFingerprint(ctx, project.ID, f.FindingKind, f.Fingerprint)
	// A lookup error (incl. port.ErrNotFound) means there is no existing
	// finding yet; only carry forward gate state when one exists.
	if lookupErr == nil {
		oldRank = existing.CurrentSeverityRank
		oldGateEffect = existing.GateEffect
		oldAnalysisState = existing.AnalysisState
	}

	// A finding that was previously verified as fixed and is now observed
	// again is a regression: the fix did not hold. The SQL upsert flips
	// state 'fixed' -> 'reopened'; we detect the pre-upsert fixed state here
	// and log an explicit regression event so consumers (gate, dashboards,
	// watchers) can react to the backslide.
	var regression bool
	var prevState string
	if lookupErr == nil && existing.State == string(finding.TechFixed) {
		regression = true
		prevState = existing.State
	}

	upserted, err := u.deps.Stores.Findings.Upsert(ctx,
		project.ID,
		f.FindingKind,
		f.Fingerprint,
		f.Title,
		severityStr(f.Severity),
		newRank,
		scoreToFloat(f.Score),
		nowTime,
		nowTime,
	)
	if err != nil {
		slog.Error("upsert finding failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
		return 0, false, fmt.Errorf("scanner %s: upsert finding %q: %w", input.Scanner, f.Fingerprint, err)
	}

	// Introduced-by-change attribution (SOLO-184): a finding observed for
	// the first time is introduced by this report; a pre-existing finding
	// with no attribution (pre-migration rows) gains it on observation.
	// Existing attribution is never rewritten here — only the explicit
	// refresh path revises it when improved evidence arrives.
	if lookupErr != nil || existing.IntroducedByReportID == nil {
		if _, err := u.deps.Stores.Findings.SetFindingIntroducedBy(ctx, upserted.ID, report.ID, textPtr(input.CommitSha)); err != nil {
			slog.Error("set introduced-by failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
			return 0, false, fmt.Errorf("scanner %s: attribute finding %q: %w", input.Scanner, f.Fingerprint, err)
		}
	}

	// Change classification (SOLO-165): against an incremental baseline a
	// finding counts as introduced only when the baseline never observed
	// it; for full scans first-seen is the classifier. Absence from an
	// incremental scan classifies nothing — partial coverage never closes.
	introduced = lookupErr != nil
	if baselineID != "" {
		seen, err := u.deps.Stores.Findings.HasOccurrence(ctx, upserted.ID, baselineID)
		if err != nil {
			slog.Error("check baseline occurrence failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
			return 0, false, fmt.Errorf("scanner %s: compare finding %q to baseline: %w", input.Scanner, f.Fingerprint, err)
		}
		introduced = !seen
	}

	if regression {
		changes := mustMarshal(map[string]any{"report_id": report.ID, "scanner": input.Scanner, "new_state": upserted.State})
		if _, err := u.deps.Stores.Findings.CreateEvent(ctx, port.FindingEventInput{
			FindingID: upserted.ID,
			EventType: "regression",
			OldValue:  &prevState,
			NewValue:  strPtr(upserted.State),
			Changes:   changes,
		}); err != nil {
			slog.Warn("log regression event failed", "finding", upserted.ID, "error", err)
		}
		if u.deps.Tracker != nil {
			u.deps.Tracker.Dispatch(ctx, tracker.Event{
				Type:         tracker.EventRegression,
				FindingID:    upserted.ID,
				ProjectSlug:  input.ProjectSlug,
				Severity:     severityStr(f.Severity),
				SeverityRank: newRank,
				Title:        f.Title,
				Fingerprint:  f.Fingerprint,
				FindingKind:  f.FindingKind,
				OccurredAt:   nowTime,
			})
		}
	}
	// New findings trigger a tracker create; regressions trigger an update.
	// Both are best-effort — the tracker swallows its own failures.
	if lookupErr != nil && u.deps.Tracker != nil {
		u.deps.Tracker.Dispatch(ctx, tracker.Event{
			Type:         tracker.EventCreated,
			FindingID:    upserted.ID,
			ProjectSlug:  input.ProjectSlug,
			Severity:     severityStr(f.Severity),
			SeverityRank: newRank,
			Title:        f.Title,
			Fingerprint:  f.Fingerprint,
			FindingKind:  f.FindingKind,
			OccurredAt:   nowTime,
		})
	}
	occ := toOccurrenceParams(f, input.Scanner)
	occ.FindingID = upserted.ID
	occ.ReportID = &report.ID
	occ.ToolVersion = textPtr(input.ScannerVersion)
	occ.ParserVersion = textPtr(input.ParserVersion)
	_, err = u.deps.Stores.Findings.CreateOccurrence(ctx, occ)
	if err != nil {
		slog.Error("create occurrence failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
		return 0, false, fmt.Errorf("scanner %s: create occurrence for %q: %w", input.Scanner, f.Fingerprint, err)
	}

	source := textPtr(input.Scanner)
	for _, d := range f.Dimensions {
		if !isCanonicalDimension(d.Key) {
			slog.Warn("drop non-canonical dimension", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "key", d.Key)
			continue
		}
		err = u.deps.Stores.Findings.UpsertDimension(ctx, port.DimensionInput{
			FindingID: upserted.ID,
			Key:       d.Key,
			Value:     d.Value,
			Source:    source,
		})
		if err != nil {
			slog.Error("upsert dimension failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
			return 0, false, fmt.Errorf("scanner %s: upsert dimension for %q: %w", input.Scanner, f.Fingerprint, err)
		}
	}

	if lookupErr == nil && (oldAnalysisState != string(finding.StateUnanalyzed) || oldGateEffect == string(finding.EffectIgnore)) {
		if err := u.applyMaterialChange(ctx, project, input, upserted, f, oldRank, oldGateEffect, oldAnalysisState); err != nil {
			return 0, false, err
		}
	}

	return 1, introduced, nil
}

// applyMaterialChange runs finding.EvaluateChange on a previously-known
// finding and, when the change demands review, marks review_required and logs
// the material-change event.
func (u *Usecases) applyMaterialChange(ctx context.Context, project port.Project, input IngestReportInput, upserted port.Finding, f domain.NormalizedFinding, oldRank int16, oldGateEffect, oldAnalysisState string) error {
	hasNewFix := false
	for _, d := range f.Dimensions {
		if d.Key == domain.DimFixedVersion && d.Value != "" {
			hasNewFix = true
			break
		}
	}

	var hadOldFix bool
	if hasNewFix {
		hadOldFix, _ = u.deps.Stores.Findings.HasDimension(ctx, upserted.ID, domain.DimFixedVersion)
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

	_, err := u.deps.Stores.Findings.UpdateAnalysis(ctx, port.UpdateAnalysisInput{
		ID:                upserted.ID,
		AnalysisState:     upserted.AnalysisState,
		GateEffect:        upserted.GateEffect,
		AnalysisSource:    upserted.AnalysisSource,
		ManualOverride:    upserted.ManualOverride,
		ReviewRequired:    true,
		AnalysisReason:    upserted.AnalysisReason,
		AnalysisExpiresAt: upserted.AnalysisExpiresAt,
	})
	if err != nil {
		slog.Error("set review_required failed", "scanner", input.Scanner, "fingerprint", f.Fingerprint, "error", err)
		return fmt.Errorf("scanner %s: set review_required for finding %q: %w", input.Scanner, f.Fingerprint, err)
	}

	changesJSON, _ := json.Marshal(change.Changes)
	_, err = u.deps.Stores.Findings.CreateEvent(ctx, port.FindingEventInput{
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

// markReportFailed transitions a report created with status 'processing' to
// 'failed' when a downstream ingest stage (finding persistence or inventory)
// errors out. Without this the report row would stay stuck in 'processing'
// forever — the unique dedup index only admits 'completed' reports, so a
// terminal 'failed' row still lets a retry re-ingest the same raw content.
// The status write is best-effort: the original ingest error is what the
// caller returns.
func (u *Usecases) markReportFailed(ctx context.Context, input IngestReportInput, report port.Report, cause error) {
	if cause == nil {
		return
	}
	msg := cause.Error()
	_, err := u.deps.Stores.Reports.UpdateStatus(ctx, report.ID, report.ProjectID, "failed", 0, &msg)
	if err != nil {
		slog.Error("mark report failed errored", "scanner", input.Scanner, "report_id", report.ID, "error", err)
		return
	}
	slog.Error("ingest failed; report marked failed", "scanner", input.Scanner, "report_id", report.ID, "error", cause)
}

// persistInventory writes the report's package references when any exist.
func (u *Usecases) persistInventory(ctx context.Context, input IngestReportInput, report port.Report, nr *domain.NormalizedReport) error {
	if len(nr.Packages) == 0 {
		return nil
	}
	if err := u.deps.Stores.Inventory.UpsertReportPackages(ctx, report.ID, toInventoryPackageParams(nr.Packages)); err != nil {
		slog.Error("persist package inventory failed", "scanner", input.Scanner, "report_id", report.ID, "error", err)
		return fmt.Errorf("scanner %s: persist package inventory: %w", input.Scanner, err)
	}
	return nil
}

// checkGateAfterIngest marks the report completed and reports whether the
// project's gate is breached. It routes through the same gate service as
// GetGateStatus (u.gate.Evaluate) so the ingest response's ThresholdBreached
// always agrees with a subsequent GET /api/v1/projects/{slug}/gate for the
// same report: both consume the batch candidate loader, waiver matching,
// reachability exemptions, and source policies.
func (u *Usecases) checkGateAfterIngest(ctx context.Context, project port.Project, input IngestReportInput, report port.Report, total int) (bool, error) {
	_, err := u.deps.Stores.Reports.UpdateStatus(ctx, report.ID, project.ID, "completed", int32(total), nil)
	if err != nil {
		slog.Error("update report status failed", "scanner", input.Scanner, "report_id", report.ID, "error", err)
		return false, fmt.Errorf("scanner %s: update report status: %w", input.Scanner, err)
	}

	u.initGate()
	minRank := gateSeverityRank(input.GateSeverity, input.GateStatus)
	decision, err := u.gate.EvaluateWithPolicies(ctx, project.ID, minRank, gatePoliciesForProject(project))
	if err != nil {
		slog.Error("gate check failed", "scanner", input.Scanner, "project", project.ID, "error", err)
		return false, fmt.Errorf("scanner %s: gate check: %w", input.Scanner, err)
	}
	return decision.Status == gate.StatusFail, nil
}

// gateSeverityRank resolves the ingest gate overrides into the severity-rank
// floor the gate service consumes. GateStatus is not part of the gate
// service's candidate prefilter (the candidate SQL already scopes to
// open/reopened state); the rank floor maps the severity strings, defaulting
// to high (rank 3) like parseMinSeverityRank.
func gateSeverityRank(severities, statuses []string) int16 {
	if len(severities) == 0 {
		return 3
	}
	minRank := int16(0)
	for _, s := range severities {
		switch s {
		case "critical":
			if 4 > minRank {
				minRank = 4
			}
		case "high":
			if 3 > minRank {
				minRank = 3
			}
		case "medium":
			if 2 > minRank {
				minRank = 2
			}
		case "low":
			if 1 > minRank {
				minRank = 1
			}
		}
	}
	if minRank == 0 {
		return 3
	}
	return minRank
}
