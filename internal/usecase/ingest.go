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

	"github.com/minh-tg/specht/internal/auth"
	"github.com/minh-tg/specht/internal/domain"
	"github.com/minh-tg/specht/internal/finding"
	"github.com/minh-tg/specht/internal/gate"
	"github.com/minh-tg/specht/internal/port"
	"github.com/minh-tg/specht/internal/scanner"
	"github.com/minh-tg/specht/internal/tracker"
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

// validateIngestInput checks required fields, canonicalizes the scan mode
// and revisions, and rejects incomplete incremental scans.
func validateIngestInput(input IngestReportInput) (IngestReportInput, error) {
	if input.ProjectSlug == "" {
		return input, fmt.Errorf("project slug is required")
	}
	if input.Scanner == "" {
		return input, fmt.Errorf("scanner name is required")
	}
	if len(input.RawData) == 0 {
		return input, fmt.Errorf("raw scan data is required")
	}
	scanMode, err := normalizeScanMode(input.ScanMode)
	if err != nil {
		return input, err
	}
	input.ScanMode = scanMode
	// Revision canonicalization: SHAs compare case-insensitively
	// everywhere, so store them canonical. Branches are case-sensitive and
	// untouched.
	input.CommitSha = normalizeRevision(input.CommitSha)
	input.BaseRevision = normalizeRevision(input.BaseRevision)
	if scanMode == ScanModeIncremental && input.BaseRevision == "" {
		return input, fmt.Errorf("incremental scan requires base_revision")
	}
	if scanMode == ScanModeIncremental && input.CommitSha != "" && input.BaseRevision == input.CommitSha {
		return input, fmt.Errorf("incremental scan requires base_revision to differ from commit_sha")
	}
	return input, nil
}

func (u *Usecases) IngestReport(ctx context.Context, input IngestReportInput) (*IngestReportOutput, error) {
	input, err := validateIngestInput(input)
	if err != nil {
		return nil, err
	}

	project, err := u.deps.Stores.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, input.ProjectSlug, err)
	}
	// HTTP requests always carry an authenticated identity. Identity-less
	// calls are reserved for trusted internal ingestion jobs.
	if auth.ContextIdentity(ctx) != nil {
		if err := u.requireProjectIngest(ctx, project.ID); err != nil {
			return nil, err
		}
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

	// Duplicate-content guard: identical bytes already completed for this
	// project ingest as a 409, before any row is written. The hash covers
	// the redacted bytes (the stored form), so reporting the same scan
	// twice collides here instead of stranding a processing row at
	// completion time.
	if err := u.rejectDuplicateContent(ctx, project.ID, input.RawData); err != nil {
		return nil, err
	}

	ctxInfo, err := u.resolveReportContext(ctx, project, input, nr)
	if err != nil {
		return nil, err
	}

	// Incremental scans resolve an effective mode before any
	// row is written: unsupported scanners and missing baselines fall
	// back to full with an explicit reason instead of recording partial
	// coverage as if it were complete.
	effectiveMode, fallbackReason, baselineID, err := u.resolveScanMode(ctx, project, sc, input)
	if err != nil {
		return nil, err
	}
	input.ScanMode = effectiveMode
	baselineID, err = u.resolveBaseRevision(ctx, project, input, baselineID)
	if err != nil {
		return nil, err
	}

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

// rejectDuplicateContent returns ErrDuplicateReport when identical (redacted)
// bytes already completed an ingest for this project.
func (u *Usecases) rejectDuplicateContent(ctx context.Context, projectID string, rawData []byte) error {
	rawHash := sha256.Sum256(rawData)
	if _, err := u.deps.Stores.Reports.FindCompletedByHash(ctx, projectID, hex.EncodeToString(rawHash[:])); err == nil {
		return ErrDuplicateReport
	} else if !errors.Is(err, port.ErrNotFound) {
		return fmt.Errorf("check duplicate report: %w", err)
	}
	return nil
}

// resolveBaseRevision fills the baseline from the base revision when scan
// mode resolution did not already provide one.
func (u *Usecases) resolveBaseRevision(ctx context.Context, project port.Project, input IngestReportInput, baselineID string) (string, error) {
	if baselineID != "" || input.BaseRevision == "" {
		return baselineID, nil
	}
	base, err := u.deps.Stores.Reports.GetCompletedByCommit(ctx, project.ID, input.Scanner, input.BaseRevision)
	if err == nil {
		return base.ID, nil
	}
	if errors.Is(err, port.ErrNotFound) {
		return "", nil
	}
	return "", fmt.Errorf("resolve base revision: %w", err)
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
	out.targetID, out.targetIdentifier = u.resolveTarget(ctx, project, input, nr)
	out.artifactID = u.resolveArtifact(ctx, project, input, nr, out.targetID)
	out.environmentID = u.resolveEnvironment(ctx, project, input)
	return out, nil
}

// resolveTarget upserts the scan target (best-effort; failures log only).
func (u *Usecases) resolveTarget(ctx context.Context, project port.Project, input IngestReportInput, nr *domain.NormalizedReport) (id, identifier string) {
	if nr.Target == nil || nr.Target.Identifier == "" {
		return "", ""
	}
	identifier = nr.Target.Identifier
	kind := nr.Target.Kind
	if kind == "" {
		kind = string(nr.ScanType)
	}
	t, err := u.deps.Stores.Targets.Upsert(ctx, project.ID, identifier, kind, identifier, input.Owner)
	if err != nil {
		slog.Warn("upsert target failed", "project", project.ID, "target", identifier, "error", err)
		return "", identifier
	}
	return t.ID, identifier
}

// resolveArtifact upserts the scanned artifact, falling back to the report
// payload for identity fields the input omits (best-effort; failures log only).
func (u *Usecases) resolveArtifact(ctx context.Context, project port.Project, input IngestReportInput, nr *domain.NormalizedReport, targetID string) string {
	artifactName := input.ArtifactName
	if artifactName == "" && nr.Artifact != nil {
		artifactName = nr.Artifact.Identifier
	}
	if artifactName == "" {
		return ""
	}
	artifactType := input.ArtifactType
	if artifactType == "" && nr.Artifact != nil {
		artifactType = nr.Artifact.Kind
	}
	if artifactType == "" {
		artifactType = string(nr.ScanType)
	}
	metadata := []byte("{}")
	if nr.Artifact != nil {
		if m := mustMarshal(nr.Artifact.Metadata); m != nil {
			metadata = m
		}
	}
	digest := input.Digest
	if digest == "" && nr.Artifact != nil {
		digest = nr.Artifact.Digest
	}
	a, err := u.deps.Stores.Artifacts.Upsert(ctx, port.ArtifactInput{
		ProjectID:    project.ID,
		TargetID:     targetID,
		ArtifactType: artifactType,
		Name:         artifactName,
		Version:      textPtr(input.ArtifactVersion),
		Digest:       textPtr(digest),
		Metadata:     metadata,
	})
	if err != nil {
		slog.Warn("upsert artifact failed", "project", project.ID, "artifact", artifactName, "error", err)
		return ""
	}
	return a.ID
}

// resolveEnvironment upserts the scan environment (best-effort; failures
// log only).
func (u *Usecases) resolveEnvironment(ctx context.Context, project port.Project, input IngestReportInput) string {
	if input.Environment == "" {
		return ""
	}
	e, err := u.deps.Stores.Environments.Upsert(ctx, project.ID, input.Environment, "development", false, "internal")
	if err != nil {
		slog.Warn("upsert environment failed", "project", project.ID, "environment", input.Environment, "error", err)
		return ""
	}
	return e.ID
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

// ingestFindingsState accumulates the ingest's cross-finding state: the
// prefetched known findings, baseline occurrences, introduced entries, and
// outcome tallies.
type ingestFindingsState struct {
	project      port.Project
	input        IngestReportInput
	report       port.Report
	baselineID   string
	nowTime      time.Time
	known        map[string]port.Finding
	knownIDs     []string
	baselineSeen map[string]bool

	seenIntroduced    map[string]bool
	introducedEntries []port.IntroducedFindingEntry
	outcome           ingestOutcome
}

// ingestReportFindings upserts each normalized finding and its occurrence,
// dimensions, and material-change events. baselineID is the incremental
// baseline report (empty for full scans); findings absent from it count as
// introduced, the rest as pre-existing.
func (u *Usecases) ingestReportFindings(ctx context.Context, project port.Project, input IngestReportInput, report port.Report, nr *domain.NormalizedReport, baselineID string) (ingestOutcome, error) {
	if len(nr.Findings) == 0 {
		return ingestOutcome{}, nil
	}
	st := &ingestFindingsState{
		project:        project,
		input:          input,
		report:         report,
		baselineID:     baselineID,
		nowTime:        now(),
		known:          make(map[string]port.Finding),
		baselineSeen:   make(map[string]bool),
		seenIntroduced: make(map[string]bool),
	}
	if err := u.prefetchKnownFindings(ctx, st, nr); err != nil {
		return ingestOutcome{}, err
	}
	if err := u.prefetchBaselineOccurrences(ctx, st); err != nil {
		return ingestOutcome{}, err
	}

	for _, f := range nr.Findings {
		if err := u.ingestOneFinding(ctx, st, f); err != nil {
			return ingestOutcome{}, err
		}
	}

	// Phase 4: Materialize introduced findings in report_introduced_findings.
	if err := u.recordIntroducedFindings(ctx, st); err != nil {
		return ingestOutcome{}, err
	}
	return st.outcome, nil
}

// prefetchKnownFindings loads every already-tracked finding whose
// fingerprint appears in the incoming report (Phase 1).
func (u *Usecases) prefetchKnownFindings(ctx context.Context, st *ingestFindingsState, nr *domain.NormalizedReport) error {
	fingerprintsByKind := make(map[string][]string)
	for _, f := range nr.Findings {
		fingerprintsByKind[f.FindingKind] = append(fingerprintsByKind[f.FindingKind], f.Fingerprint)
	}

	var knownIDs []string
	for kind, fps := range fingerprintsByKind {
		known, err := u.deps.Stores.Findings.ListFindingsByFingerprints(ctx, st.project.ID, kind, fps)
		if err != nil {
			slog.Error("pre-fetch findings by fingerprints failed", "scanner", st.input.Scanner, "error", err)
			return fmt.Errorf("scanner %s: pre-fetch findings: %w", st.input.Scanner, err)
		}
		for _, k := range known {
			st.known[k.FindingKind+"\x00"+k.Fingerprint] = k
			knownIDs = append(knownIDs, k.ID)
		}
	}
	st.knownIDs = knownIDs
	return nil
}

// prefetchBaselineOccurrences marks which known findings the baseline report
// already saw (empty baselineID skips the query).
func (u *Usecases) prefetchBaselineOccurrences(ctx context.Context, st *ingestFindingsState) error {
	if st.baselineID == "" || len(st.knownIDs) == 0 {
		return nil
	}
	presentIDs, err := u.deps.Stores.Findings.ListFindingIDsPresentInReport(ctx, st.baselineID, st.knownIDs)
	if err != nil {
		slog.Error("pre-fetch baseline occurrences failed", "scanner", st.input.Scanner, "error", err)
		return fmt.Errorf("scanner %s: pre-fetch baseline occurrences: %w", st.input.Scanner, err)
	}
	for _, id := range presentIDs {
		st.baselineSeen[id] = true
	}
	return nil
}

// classifyIngestChange decides whether a finding counts as introduced for
// this report: regressions and baseline-absent or
// unseen findings are introduced; everything else pre-existed.
func classifyIngestChange(exists, regression bool, baselineID string, baselineSeen bool) (introduced bool, changeType string) {
	if regression {
		return true, "regression"
	}
	if baselineID != "" {
		if !exists || !baselineSeen {
			return true, "new"
		}
		return false, ""
	}
	if !exists {
		return true, "new"
	}
	return false, ""
}

// ingestOneFinding upserts one normalized finding plus its attribution,
// occurrence, dimensions, events, and material-change evaluation.
func (u *Usecases) ingestOneFinding(ctx context.Context, st *ingestFindingsState, f domain.NormalizedFinding) error {
	existing, exists := st.known[f.FindingKind+"\x00"+f.Fingerprint]
	newRank := severityRank(f.Severity)

	upserted, err := u.upsertFindingRow(ctx, st, f, newRank)
	if err != nil {
		return err
	}
	if err := u.attributeFinding(ctx, st, upserted, exists, existing); err != nil {
		return err
	}

	regression := exists && existing.State == string(finding.TechFixed)
	introduced, changeType := classifyIngestChange(
		exists, regression, st.baselineID,
		exists && st.baselineSeen[existing.ID],
	)
	st.tallyIngest(introduced, changeType, upserted.ID)

	if regression {
		u.logRegressionEvent(ctx, st, upserted, f, newRank, existing.State)
	}
	u.dispatchCreatedEvent(ctx, st, upserted, f, newRank, !exists)

	if err := u.createFindingOccurrence(ctx, st, upserted, f); err != nil {
		return err
	}
	if err := u.upsertFindingDimensions(ctx, st, upserted, f); err != nil {
		return err
	}

	if exists && (existing.AnalysisState != string(finding.StateUnanalyzed) || existing.GateEffect == string(finding.EffectIgnore)) {
		return u.applyMaterialChange(ctx, st.input, upserted, f,
			existing.CurrentSeverityRank, existing.GateEffect, existing.AnalysisState)
	}
	return nil
}

// tallyIngest records the introduced/pre-existing counters, deduplicating
// introduced entries by finding ID.
func (s *ingestFindingsState) tallyIngest(introduced bool, changeType, upsertedID string) {
	if !introduced {
		s.outcome.preExisting++
		s.outcome.total++
		return
	}
	if !s.seenIntroduced[upsertedID] {
		s.seenIntroduced[upsertedID] = true
		s.introducedEntries = append(s.introducedEntries, port.IntroducedFindingEntry{
			FindingID:  upsertedID,
			ChangeType: changeType,
		})
	}
	s.outcome.introduced++
	s.outcome.total++
}

// upsertFindingRow writes the finding row and returns what was written.
func (u *Usecases) upsertFindingRow(ctx context.Context, st *ingestFindingsState, f domain.NormalizedFinding, newRank int16) (port.Finding, error) {
	upserted, err := u.deps.Stores.Findings.Upsert(ctx, port.UpsertFindingInput{
		ProjectID:    st.project.ID,
		FindingKind:  f.FindingKind,
		Fingerprint:  f.Fingerprint,
		Title:        f.Title,
		Severity:     severityStr(f.Severity),
		SeverityRank: newRank,
		Score:        scoreToFloat(f.Score),
		FirstSeen:    st.nowTime,
		LastSeen:     st.nowTime,
	})
	if err != nil {
		slog.Error("upsert finding failed", "scanner", st.input.Scanner, "fingerprint", f.Fingerprint, "error", err)
		return port.Finding{}, fmt.Errorf("scanner %s: upsert finding %q: %w", st.input.Scanner, f.Fingerprint, err)
	}
	return upserted, nil
}

// attributeFinding keeps legacy attribution on the finding row for
// unattributed findings.
func (u *Usecases) attributeFinding(ctx context.Context, st *ingestFindingsState, upserted port.Finding, exists bool, existing port.Finding) error {
	if exists && existing.IntroducedByReportID != nil {
		return nil
	}
	if _, err := u.deps.Stores.Findings.SetFindingIntroducedBy(ctx, upserted.ID, st.report.ID, textPtr(st.input.CommitSha)); err != nil {
		slog.Error("set introduced-by failed", "scanner", st.input.Scanner, "fingerprint", upserted.Fingerprint, "error", err)
		return fmt.Errorf("scanner %s: attribute finding %q: %w", st.input.Scanner, upserted.Fingerprint, err)
	}
	return nil
}

// logRegressionEvent records the regression audit event and dispatches the
// tracker notification (best-effort event, dispatch honors the tracker nil).
func (u *Usecases) logRegressionEvent(ctx context.Context, st *ingestFindingsState, upserted port.Finding, f domain.NormalizedFinding, newRank int16, prevState string) {
	changes := mustMarshal(map[string]any{"report_id": st.report.ID, "scanner": st.input.Scanner, "new_state": upserted.State})
	if _, err := u.deps.Stores.Findings.CreateEvent(ctx, port.FindingEventInput{
		FindingID: upserted.ID,
		EventType: "regression",
		OldValue:  &prevState,
		NewValue:  strPtr(upserted.State),
		Changes:   changes,
	}); err != nil {
		slog.Warn("log regression event failed", "finding", upserted.ID, "error", err)
	}
	u.trackerDispatch(ctx, st, upserted, f, newRank, tracker.EventRegression)
}

// dispatchCreatedEvent notifies the tracker about a newly created finding.
func (u *Usecases) dispatchCreatedEvent(ctx context.Context, st *ingestFindingsState, upserted port.Finding, f domain.NormalizedFinding, newRank int16, created bool) {
	if created {
		u.trackerDispatch(ctx, st, upserted, f, newRank, tracker.EventCreated)
	}
}

// trackerDispatch emits one finding event to the tracker when configured.
func (u *Usecases) trackerDispatch(ctx context.Context, st *ingestFindingsState, upserted port.Finding, f domain.NormalizedFinding, newRank int16, eventType string) {
	if u.deps.Tracker == nil {
		return
	}
	u.deps.Tracker.Dispatch(ctx, tracker.Event{
		Type:         eventType,
		FindingID:    upserted.ID,
		ProjectSlug:  st.input.ProjectSlug,
		Severity:     severityStr(f.Severity),
		SeverityRank: newRank,
		Title:        f.Title,
		Fingerprint:  f.Fingerprint,
		FindingKind:  f.FindingKind,
		OccurredAt:   st.nowTime,
	})
}

// createFindingOccurrence writes the scan occurrence for this finding.
func (u *Usecases) createFindingOccurrence(ctx context.Context, st *ingestFindingsState, upserted port.Finding, f domain.NormalizedFinding) error {
	occ := toOccurrenceParams(f, st.input.Scanner)
	occ.FindingID = upserted.ID
	occ.ReportID = &st.report.ID
	occ.ToolVersion = textPtr(st.input.ScannerVersion)
	occ.ParserVersion = textPtr(st.input.ParserVersion)
	if _, err := u.deps.Stores.Findings.CreateOccurrence(ctx, occ); err != nil {
		slog.Error("create occurrence failed", "scanner", st.input.Scanner, "fingerprint", f.Fingerprint, "error", err)
		return fmt.Errorf("scanner %s: create occurrence for %q: %w", st.input.Scanner, f.Fingerprint, err)
	}
	return nil
}

// upsertFindingDimensions stores canonical dimensions, dropping (with a
// warning) anything the fingerprint contract does not recognize.
func (u *Usecases) upsertFindingDimensions(ctx context.Context, st *ingestFindingsState, upserted port.Finding, f domain.NormalizedFinding) error {
	source := textPtr(st.input.Scanner)
	for _, d := range f.Dimensions {
		if !isCanonicalDimension(d.Key) {
			slog.Warn("drop non-canonical dimension", "scanner", st.input.Scanner, "fingerprint", f.Fingerprint, "key", d.Key)
			continue
		}
		if err := u.deps.Stores.Findings.UpsertDimension(ctx, port.DimensionInput{
			FindingID: upserted.ID,
			Key:       d.Key,
			Value:     d.Value,
			Source:    source,
		}); err != nil {
			slog.Error("upsert dimension failed", "scanner", st.input.Scanner, "fingerprint", f.Fingerprint, "error", err)
			return fmt.Errorf("scanner %s: upsert dimension for %q: %w", st.input.Scanner, f.Fingerprint, err)
		}
	}
	return nil
}

// recordIntroducedFindings materializes introduced findings in
// report_introduced_findings (Phase 4).
func (u *Usecases) recordIntroducedFindings(ctx context.Context, st *ingestFindingsState) error {
	if len(st.introducedEntries) == 0 {
		return nil
	}
	var basePtr *string
	if st.baselineID != "" {
		basePtr = &st.baselineID
	}
	if err := u.deps.Stores.Findings.RecordReportIntroducedFindings(ctx, st.report.ID, basePtr, st.introducedEntries); err != nil {
		slog.Error("record report introduced findings failed", "scanner", st.input.Scanner, "report_id", st.report.ID, "error", err)
		return fmt.Errorf("scanner %s: record report introduced findings: %w", st.input.Scanner, err)
	}
	return nil
}

// applyMaterialChange runs finding.EvaluateChange on a previously-known
// finding and, when the change demands review, marks review_required and logs
// the material-change event.
func (u *Usecases) applyMaterialChange(ctx context.Context, input IngestReportInput, upserted port.Finding, f domain.NormalizedFinding, oldRank int16, oldGateEffect, oldAnalysisState string) error {
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
		if errors.Is(err, port.ErrDuplicateReport) {
			u.deleteDuplicateReport(ctx, project.ID, report.ID)
			return false, ErrDuplicateReport
		}
		slog.Error("update report status failed", "scanner", input.Scanner, "report_id", report.ID, "error", err)
		return false, fmt.Errorf("scanner %s: update report status: %w", input.Scanner, err)
	}

	u.initGate()
	minRank := u.effectiveSeverityFloor(ctx, project, input.GateSeverity)
	policies := gatePoliciesForProject(project)
	var decision gate.Decision
	if input.GateIntroducedOnly {
		decision, err = u.gate.EvaluateIntroducedOnly(ctx, project.ID, minRank, report.ID, policies)
	} else {
		decision, err = u.gate.EvaluateWithPolicies(ctx, project.ID, minRank, policies)
	}
	if err != nil {
		// Duplicate-content race: a twin ingest completed first, so the
		// partial dedup index rejected this completion. Remove the
		// orphaned processing row and report the duplicate.
		if errors.Is(err, port.ErrDuplicateReport) {
			u.deleteDuplicateReport(ctx, project.ID, report.ID)
			return false, ErrDuplicateReport
		}
		slog.Error("gate check failed", "scanner", input.Scanner, "project", project.ID, "error", err)
		return false, fmt.Errorf("scanner %s: gate check: %w", input.Scanner, err)
	}
	return decision.Status == gate.StatusFail, nil
}

// deleteDuplicateReport removes a processing row orphaned by a lost
// duplicate race. Occurrences cascade; shared finding rows are untouched.
// Failures log only: the row is garbage either way (retention purges
// processing rows never, so leaving it would strand it permanently —
// hence best-effort delete here, loud log on failure).
func (u *Usecases) deleteDuplicateReport(ctx context.Context, projectID, reportID string) {
	if err := u.deps.Stores.Reports.DeleteReport(ctx, reportID, projectID); err != nil {
		slog.Error("delete duplicate report failed", "report", reportID, "error", err)
	}
}

// gateSeverityRank resolves the ingest gate overrides into the severity-rank
// floor the gate service consumes. GateStatus is not part of the gate
// service's candidate prefilter (the candidate SQL already scopes to
// open/reopened state); the rank floor maps the severity strings, defaulting
// to high (rank 3) like parseMinSeverityRank.
func gateSeverityRank(severities, _ []string) int16 {
	minRank := int16(0)
	for _, s := range severities {
		if r, ok := severityLabelRank[s]; ok && r > minRank {
			minRank = r
		}
	}
	if minRank == 0 {
		return 3
	}
	return minRank
}

// severityLabelRank maps known severity labels to their rank.
var severityLabelRank = map[string]int16{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
}
