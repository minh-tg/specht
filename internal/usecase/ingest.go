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

	// The scan-scope hash is computed before the replay lookup and before any
	// write: the replay key is (project, raw hash, commit, scope), so the
	// same bytes at the same commit only replay within one scope. A PR-branch
	// scan and its fast-forward merge on main share bytes and commit but not
	// branch, so each keeps its own report and its own auto-fix run.
	scopeHash := scanScopeHash(input, nr)

	// Replay guard: identical input for the same project, commit, and scope
	// that already completed answers with the stored report instead of
	// writing a second one. The hash covers the redacted bytes (the stored
	// form). A different commit or scope with the same bytes ingests
	// normally: scanner output is often byte-identical when nothing changed.
	replayID, err := u.findReplayReport(ctx, project.ID, input.RawData, input.CommitSha, scopeHash)
	if err != nil {
		return nil, err
	}
	if replayID != "" {
		return u.replayReport(ctx, project, input, replayID)
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

	report, err := u.createReport(ctx, project, input, nr, ctxInfo, scopeHash)
	if err != nil {
		return nil, err
	}

	outcome, err := u.ingestReportFindings(ctx, project, input, report, nr, baselineID)
	if err != nil {
		u.markReportFailed(ctx, input, report, reportFailureFindings, err)
		return nil, err
	}

	if err := u.persistInventory(ctx, input, report, nr); err != nil {
		u.markReportFailed(ctx, input, report, reportFailureInventory, err)
		return nil, err
	}

	// Scan-equivalence auto-fix: runs after every finding is persisted and
	// before the threshold check so the response reflects the post-fix state.
	if err := u.autoFixAbsentFindings(ctx, project, input, report, nr, scopeHash); err != nil {
		u.markReportFailed(ctx, input, report, reportFailureAutoFix, err)
		return nil, err
	}

	thresholdBreached, replay, err := u.checkGateAfterIngest(ctx, project, input, report, outcome.total, scopeHash)
	if err != nil {
		return nil, err
	}
	if replay != nil {
		return replay, nil
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

// autoFixAbsentFindings is the scan-equivalence auto-fix writer: when a
// full scan normalized to completeness "complete", findings whose most recent
// observation came from an equivalent complete scan of the same scope and
// that this report no longer observes move to fixed, each with a
// state_changed event naming the source report. Incremental scans prove
// nothing by absence, and parsers that cannot vouch for completeness
// default to unknown, neither of which ever reaches the store.
func (u *Usecases) autoFixAbsentFindings(ctx context.Context, project port.Project, input IngestReportInput, report port.Report, nr *domain.NormalizedReport, scopeHash string) error {
	if input.ScanMode != ScanModeFull || nr.Completeness != domain.CompletenessComplete {
		return nil
	}
	fixed, err := u.deps.Stores.Findings.MarkAbsentFindingsFixed(ctx, project.ID, scopeHash, report.ID)
	if err != nil {
		return fmt.Errorf("auto-fix absent findings: %w", err)
	}
	if len(fixed) > 0 {
		ids := make([]string, 0, len(fixed))
		for _, f := range fixed {
			ids = append(ids, f.ID)
		}
		changes := mustMarshal(map[string]any{"report_id": report.ID, "scanner": input.Scanner, "new_state": "fixed"})
		// One statement for the whole closure keeps the ingest
		// query-count budget independent of how many findings close.
		if err := u.deps.Stores.Findings.BulkCreateEvents(ctx, ids, port.FindingEventInput{
			EventType: "state_changed",
			NewValue:  strPtr("fixed"),
			Changes:   changes,
		}); err != nil {
			slog.Warn("log auto-fix events failed", "count", len(ids), "error", err)
		}
	}
	for _, f := range fixed {
		if u.deps.Tracker != nil {
			u.deps.Tracker.Dispatch(ctx, tracker.Event{
				Type:         tracker.EventVerifiedFixed,
				FindingID:    f.ID,
				ProjectSlug:  input.ProjectSlug,
				Severity:     f.CurrentSeverity,
				SeverityRank: f.CurrentSeverityRank,
				Title:        f.CurrentTitle,
				Fingerprint:  f.Fingerprint,
				FindingKind:  f.FindingKind,
				OccurredAt:   time.Now(),
			})
		}
	}
	return nil
}

// findReplayReport returns the id of a completed report whose (redacted)
// bytes, commit, and scan scope match this ingest, or the empty string when
// the content is new for this commit and scope. A NULL stored commit or scope
// and an empty request one are the same key.
func (u *Usecases) findReplayReport(ctx context.Context, projectID string, rawData []byte, commit, scopeHash string) (string, error) {
	rawHash := sha256.Sum256(rawData)
	id, err := u.deps.Stores.Reports.FindCompletedByReplayKey(ctx, projectID, hex.EncodeToString(rawHash[:]), commit, scopeHash)
	if err == nil {
		return id, nil
	}
	if errors.Is(err, port.ErrNotFound) {
		return "", nil
	}
	return "", fmt.Errorf("check duplicate report: %w", err)
}

// replayReport answers an identical re-upload for the same commit: it
// re-evaluates the stored report's gate under this request's options (which
// can only tighten policy) and returns the stored report with Replayed set.
// Findings, occurrences, and events are left untouched.
func (u *Usecases) replayReport(ctx context.Context, project port.Project, input IngestReportInput, reportID string) (*IngestReportOutput, error) {
	report, err := u.deps.Stores.Reports.GetByID(ctx, reportID)
	if err != nil {
		return nil, fmt.Errorf("load report %q for replay: %w", reportID, err)
	}
	breached, err := u.evaluateIngestGate(ctx, project, input, reportID)
	if err != nil {
		return nil, err
	}
	introduced, preExisting := u.replayCounts(ctx, project.ID, report)
	slog.Info("ingest replay", "project", project.ID, "report", reportID, "commit", input.CommitSha)
	return &IngestReportOutput{
		ReportID:          reportID,
		TotalFindings:     reportTotalFindings(report),
		ThresholdBreached: breached,
		ScanMode:          report.ScanMode,
		IntroducedCount:   introduced,
		PreExistingCount:  preExisting,
		Replayed:          true,
	}, nil
}

// replayCounts splits a replayed report's findings into introduced and
// pre-existing. The introduced set is the one materialized at ingest time;
// anything the report counted beyond it is pre-existing. A failed read only
// costs the split, never the replay.
func (u *Usecases) replayCounts(ctx context.Context, projectID string, report port.Report) (int, int) {
	total := reportTotalFindings(report)
	introduced, err := u.deps.Stores.Findings.ListIntroducedByReport(ctx, projectID, report.ID)
	if err != nil {
		slog.Warn("replay introduced count failed", "report", report.ID, "error", err)
		return 0, total
	}
	if len(introduced) > total {
		return total, 0
	}
	return len(introduced), total - len(introduced)
}

// reportTotalFindings reads a stored report's finding count, treating a
// missing count as zero.
func reportTotalFindings(report port.Report) int {
	if report.TotalFindings == nil {
		return 0
	}
	return int(*report.TotalFindings)
}

// findBaselineReport resolves a base revision to a completed full report.
// A commit SHA matches the newest full report for that exact commit. CI
// passes a branch name for pull requests, so when no commit matches, the
// newest full report on that branch is the baseline.
func (u *Usecases) findBaselineReport(ctx context.Context, projectID, scanner, revision string) (port.CompletedReport, error) {
	base, err := u.deps.Stores.Reports.GetCompletedByCommit(ctx, projectID, scanner, revision)
	if !errors.Is(err, port.ErrNotFound) {
		return base, err
	}
	return u.deps.Stores.Reports.GetLatestFullByBranch(ctx, projectID, scanner, revision)
}

// resolveBaseRevision fills the baseline from the base revision when scan
// mode resolution did not already provide one.
func (u *Usecases) resolveBaseRevision(ctx context.Context, project port.Project, input IngestReportInput, baselineID string) (string, error) {
	if baselineID != "" || input.BaseRevision == "" {
		return baselineID, nil
	}
	base, err := u.findBaselineReport(ctx, project.ID, input.Scanner, input.BaseRevision)
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
	base, err := u.findBaselineReport(ctx, project.ID, input.Scanner, input.BaseRevision)
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
// raw-data hash collision. scopeHash covers the scan scope (see
// scopeHashMaterial) and is computed before the replay lookup, so content
// scanned against a different target, artifact, branch, or environment never
// shares a scope.
func (u *Usecases) createReport(ctx context.Context, project port.Project, input IngestReportInput, nr *domain.NormalizedReport, ctxInfo reportContext, scopeHash string) (port.Report, error) {
	rawHash := sha256.Sum256(input.RawData)

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
		ScanScopeHash:    scopeHash,
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
// computed from: the scanner, target, artifact name, branch, and environment.
// Commit SHA and artifact version are left out on purpose. Auto-fix closes a
// finding only when a scan of the same scope observed it, so a later commit
// on the same branch must land in the same scope as the commit before it.
// The target enters with its build-specific parts removed (see
// scopeTargetIdentifier).
func scopeHashMaterial(input IngestReportInput, nr *domain.NormalizedReport) string {
	target := ""
	if nr.Target != nil {
		target = scopeTargetIdentifier(nr.Target.Kind, nr.Target.Identifier)
	}
	return strings.Join([]string{
		input.Scanner,
		target,
		input.ArtifactName,
		input.Branch,
		input.Environment,
	}, "\x00")
}

// scanScopeHash returns the hex SHA-256 of the scope material for one request
// and its parsed report. It reads no resolved row and writes nothing, so the
// ingest can compute it before the replay lookup.
func scanScopeHash(input IngestReportInput, nr *domain.NormalizedReport) string {
	sum := sha256.Sum256([]byte(scopeHashMaterial(input, nr)))
	return hex.EncodeToString(sum[:])
}

// scopeTargetIdentifier strips the parts of a target identifier that change on
// every build without changing what was scanned: the tag and digest of a
// container image reference, and the version of an SBOM component. Only the
// kinds named here are rewritten, so a filesystem path containing "@" or ":"
// keeps its exact spelling.
func scopeTargetIdentifier(kind, identifier string) string {
	switch kind {
	case "container_image":
		return trimImageReference(identifier)
	case "package":
		if i := strings.LastIndex(identifier, "@"); i > 0 {
			return identifier[:i]
		}
	}
	return identifier
}

// trimImageReference drops a trailing @<algorithm>:<hex> digest, then a :tag
// that sits in the last path segment. A colon before the last slash is a
// registry port and stays.
func trimImageReference(ref string) string {
	if i := strings.LastIndex(ref, "@"); i >= 0 && isDigestSuffix(ref[i+1:]) {
		ref = ref[:i]
	}
	if colon := strings.LastIndex(ref, ":"); colon > strings.LastIndex(ref, "/") {
		ref = ref[:colon]
	}
	return ref
}

// isDigestSuffix reports whether s has the shape algorithm:hex.
func isDigestSuffix(s string) bool {
	algorithm, digest, ok := strings.Cut(s, ":")
	if !ok || algorithm == "" || digest == "" {
		return false
	}
	for _, c := range digest {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
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
	batchStore        port.FindingIngestBatchStore
	occurrences       []port.OccurrenceInput
	dimensions        []port.DimensionInput
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
	batchStore, _ := u.deps.Stores.Findings.(port.FindingIngestBatchStore)
	st := &ingestFindingsState{
		project:        project,
		input:          input,
		report:         report,
		baselineID:     baselineID,
		nowTime:        now(),
		known:          make(map[string]port.Finding),
		baselineSeen:   make(map[string]bool),
		seenIntroduced: make(map[string]bool),
		batchStore:     batchStore,
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
	if err := u.flushIngestBatches(ctx, st); err != nil {
		return ingestOutcome{}, err
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

	if st.batchStore == nil {
		if err := u.createFindingOccurrence(ctx, st, upserted, f); err != nil {
			return err
		}
	} else {
		st.occurrences = append(st.occurrences, findingOccurrenceInput(st, upserted, f))
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

// findingOccurrenceInput builds the scan occurrence for this finding.
func findingOccurrenceInput(st *ingestFindingsState, upserted port.Finding, f domain.NormalizedFinding) port.OccurrenceInput {
	occ := toOccurrenceParams(f, st.input.Scanner)
	occ.FindingID = upserted.ID
	occ.ReportID = &st.report.ID
	occ.ToolVersion = textPtr(st.input.ScannerVersion)
	occ.ParserVersion = textPtr(st.input.ParserVersion)
	return occ
}

// createFindingOccurrence writes one scan occurrence for stores without batch support.
func (u *Usecases) createFindingOccurrence(ctx context.Context, st *ingestFindingsState, upserted port.Finding, f domain.NormalizedFinding) error {
	occ := findingOccurrenceInput(st, upserted, f)
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
		dimension := port.DimensionInput{
			FindingID: upserted.ID,
			Key:       d.Key,
			Value:     d.Value,
			Source:    source,
		}
		if st.batchStore != nil && d.Key != domain.DimFixedVersion {
			st.dimensions = append(st.dimensions, dimension)
			continue
		}
		if err := u.deps.Stores.Findings.UpsertDimension(ctx, dimension); err != nil {
			slog.Error("upsert dimension failed", "scanner", st.input.Scanner, "fingerprint", f.Fingerprint, "error", err)
			return fmt.Errorf("scanner %s: upsert dimension for %q: %w", st.input.Scanner, f.Fingerprint, err)
		}
	}
	return nil
}

// flushIngestBatches persists staged occurrences and non-fixed dimensions for batch-capable stores.
func (u *Usecases) flushIngestBatches(ctx context.Context, st *ingestFindingsState) error {
	if st.batchStore == nil {
		return nil
	}
	if len(st.occurrences) > 0 {
		if err := st.batchStore.BulkCreateOccurrences(ctx, st.occurrences); err != nil {
			slog.Error("bulk create occurrences failed", "scanner", st.input.Scanner, "error", err)
			return fmt.Errorf("scanner %s: bulk create occurrences: %w", st.input.Scanner, err)
		}
	}
	if len(st.dimensions) > 0 {
		if err := st.batchStore.BulkUpsertDimensions(ctx, st.input.Scanner, st.dimensions); err != nil {
			slog.Error("bulk upsert dimensions failed", "scanner", st.input.Scanner, "error", err)
			return fmt.Errorf("scanner %s: bulk upsert dimensions: %w", st.input.Scanner, err)
		}
	}
	return nil
}

// recordIntroducedFindings materializes introduced findings in report_introduced_findings.
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
		var err error
		hadOldFix, err = u.deps.Stores.Findings.HasDimension(ctx, upserted.ID, domain.DimFixedVersion)
		if err != nil {
			return fmt.Errorf("check previous fixed version for finding %q: %w", upserted.ID, err)
		}
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

// Reasons stored in error_message for a failed report. Store errors can carry
// SQL text or connection details, so the stored value is one of these fixed
// strings; the raw error is written to the server log only.
const (
	reportFailureFindings  = "Internal error: could not store findings."
	reportFailureInventory = "Internal error: could not persist package inventory."
	reportFailureAutoFix   = "Internal error: could not close findings absent from this scan."
	// reportFailureGeneric is what a response shows for a stored failure
	// reason that is not one of the fixed reasons above. Rows written before
	// the fixed reasons existed hold raw store errors.
	reportFailureGeneric = "Internal error: the report could not be processed."
)

// reportFailureReasonForResponse decides what a report response shows for its
// stored failure reason. Only the fixed reasons pass through. Any other
// non-empty value is replaced with reportFailureGeneric, so raw store output
// from older rows never reaches a client. Nil and empty values are returned
// unchanged.
func reportFailureReasonForResponse(stored *string) *string {
	if stored == nil || *stored == "" {
		return stored
	}
	switch *stored {
	case reportFailureFindings, reportFailureInventory, reportFailureAutoFix:
		return stored
	default:
		generic := reportFailureGeneric
		return &generic
	}
}

// markReportFailed transitions a report created with status 'processing' to
// 'failed' when a downstream ingest stage (finding persistence, inventory, or
// auto-fix) errors out. Without this the report row would stay stuck in
// 'processing' forever — the unique dedup index only admits 'completed'
// reports, so a terminal 'failed' row still lets a retry re-ingest the same
// raw content. The status write is best-effort: the original ingest error is
// what the caller returns.
func (u *Usecases) markReportFailed(ctx context.Context, input IngestReportInput, report port.Report, reason string, cause error) {
	if cause == nil {
		return
	}
	msg := reason
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
//
// When completion loses a duplicate-content race, the returned replay output
// answers as the winner's report instead of an error. The bool return is
// meaningless then; the caller returns the replay output directly.
func (u *Usecases) checkGateAfterIngest(ctx context.Context, project port.Project, input IngestReportInput, report port.Report, total int, scopeHash string) (bool, *IngestReportOutput, error) {
	_, err := u.deps.Stores.Reports.UpdateStatus(ctx, report.ID, project.ID, "completed", int32(total), nil)
	if err != nil {
		if errors.Is(err, port.ErrDuplicateReport) {
			return u.replayRaceWinner(ctx, project, input, report.ID, scopeHash)
		}
		slog.Error("update report status failed", "scanner", input.Scanner, "report_id", report.ID, "error", err)
		return false, nil, fmt.Errorf("scanner %s: update report status: %w", input.Scanner, err)
	}

	breached, err := u.evaluateIngestGate(ctx, project, input, report.ID)
	if err != nil {
		// Duplicate-content race: a twin ingest completed first, so the
		// partial dedup index rejected this completion.
		if errors.Is(err, port.ErrDuplicateReport) {
			return u.replayRaceWinner(ctx, project, input, report.ID, scopeHash)
		}
		slog.Error("gate check failed", "scanner", input.Scanner, "project", project.ID, "error", err)
		return false, nil, fmt.Errorf("scanner %s: gate check: %w", input.Scanner, err)
	}
	return breached, nil, nil
}

// evaluateIngestGate runs the post-ingest threshold check for one report with
// the request's gate options. Replays share it so a replay's verdict matches
// what the same request would have produced at ingest time.
func (u *Usecases) evaluateIngestGate(ctx context.Context, project port.Project, input IngestReportInput, reportID string) (bool, error) {
	u.initGate()
	minRank := u.effectiveSeverityFloor(ctx, project, input.GateSeverity)
	policies := gatePoliciesForProject(project)
	var decision gate.Decision
	var err error
	if input.GateIntroducedOnly {
		decision, err = u.gate.EvaluateIntroducedOnly(ctx, project.ID, minRank, reportID, policies)
	} else {
		decision, err = u.gate.EvaluateWithPolicies(ctx, project.ID, minRank, policies)
	}
	if err != nil {
		return false, err
	}
	return decision.Status == gate.StatusFail, nil
}

// replayRaceWinner answers a lost duplicate-completion race: a twin ingest of
// the same scope, commit, and bytes completed first, so this report's
// completion violated the dedup index. The orphaned processing row is removed
// (moving any finding attribution it introduced to the winner) and the winner
// is replayed. ErrDuplicateReport is returned only when the winner cannot be
// found, for example when a concurrent retention purge removed it between the
// index violation and the lookup. That is the one remaining case that answers
// 409.
func (u *Usecases) replayRaceWinner(ctx context.Context, project port.Project, input IngestReportInput, orphanID, scopeHash string) (bool, *IngestReportOutput, error) {
	winnerID, err := u.findReplayReport(ctx, project.ID, input.RawData, input.CommitSha, scopeHash)
	// The orphaned processing row is garbage whether or not a winner resolves,
	// so cleanup always runs. With a winner, cleanup moves the findings the
	// loser introduced to the winner in the same transaction as the delete.
	u.deleteDuplicateReport(ctx, project.ID, orphanID, winnerID)
	if err != nil {
		return false, nil, err
	}
	if winnerID == "" {
		return false, nil, ErrDuplicateReport
	}
	out, err := u.replayReport(ctx, project, input, winnerID)
	if err != nil {
		return false, nil, err
	}
	return out.ThresholdBreached, out, nil
}

// deleteDuplicateReport removes a processing row orphaned by a lost duplicate
// race. When the winner is known it also re-points the findings the orphan
// introduced at the winner, in the same transaction, so a shared finding row
// keeps its attribution instead of nulling when the orphan goes. Occurrences
// and the orphan's report_introduced_findings rows cascade; the winner's own
// rows are untouched. Failures log only: the row is garbage either way
// (retention purges processing rows never, so leaving it would strand it
// permanently, hence best-effort delete here, loud log on failure).
func (u *Usecases) deleteDuplicateReport(ctx context.Context, projectID, reportID, winnerID string) {
	var err error
	if winnerID == "" {
		err = u.deps.Stores.Reports.DeleteReport(ctx, reportID, projectID)
	} else {
		err = u.deps.Stores.Reports.DeleteDuplicateReport(ctx, reportID, projectID, winnerID)
	}
	if err != nil {
		slog.Error("delete duplicate report failed", "report", reportID, "error", err)
	}
}

// gateSeverityRank resolves the ingest gate overrides into the severity-rank
// floor the gate service consumes. GateStatus is not part of the gate
// service's candidate prefilter (the candidate SQL already scopes to
// open/reopened state); the rank floor maps the severity strings, defaulting
// to high (rank 3) like parseMinSeverityRank.
// gateSeverityRank maps the caller's severity list to the blocking floor:
// the LOWEST severity named, so every listed severity blocks (parity with
// parseMinSeverityRank). Unknown labels are skipped; an empty or wholly
// unknown list floors at high (rank 3), failing closed toward blocking.
func gateSeverityRank(severities, _ []string) int16 {
	minRank := int16(0)
	for _, s := range severities {
		r, ok := severityLabelRank[s]
		if !ok || r == 0 {
			continue
		}
		if minRank == 0 || r < minRank {
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
