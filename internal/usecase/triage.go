package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/finding"
	"github.com/minh-tg/specht/internal/gate"
	"github.com/minh-tg/specht/internal/port"
)

var (
	ErrFindingNotFound = errors.New("finding not found")
	ErrReasonRequired  = errors.New("reason is required for this analysis state")
	ErrExpiryRequired  = errors.New("expiry is required for accepted_risk and wont_fix")
	ErrExpiryPassed    = errors.New("expiry must be in the future")
	ErrInvalidState    = errors.New("invalid analysis state")
	ErrTooManyFindings = errors.New("too many findings in one request")
	ErrReasonTooLong   = errors.New("reason is too long")
	// ErrAnalysisConflict means the finding no longer matches the state the
	// caller based its write on (a stale expected_state, or an undo of an
	// event that is not the newest analysis event).
	ErrAnalysisConflict = port.ErrAnalysisConflict
	// ErrUndoUnavailable means the event cannot be undone because it holds
	// no snapshot of the earlier analysis (written before snapshots existed,
	// or by bulk triage or the review flag).
	ErrUndoUnavailable = errors.New("this change cannot be undone")
	// ErrPreviousExpiryPassed means the earlier analysis expired in the
	// meantime, so restoring it would bring back an expired decision.
	ErrPreviousExpiryPassed = errors.New("the previous analysis has already expired")
	ErrInvalidEventID       = errors.New("invalid event id")
)

const (
	// MaxBulkTriageFindings bounds the finding ids in one bulk triage call,
	// which does a lookup, an access check and an update for each.
	MaxBulkTriageFindings = 1000
	// MaxTriageReasonBytes bounds a triage reason. The reason is copied onto
	// the event of every finding it is applied to, so an unbounded one
	// multiplies into the database by the size of the batch.
	MaxTriageReasonBytes = 4096
)

// TriageInput sets a finding's analysis state with an optional reason and expiry.
type TriageInput struct {
	FindingID         string
	AnalysisState     string
	Reason            string
	AnalysisExpiresAt *time.Time
	UserID            string
	// ExpectedState, when set, makes the write conditional on the finding
	// still being in that analysis state.
	ExpectedState string
}

// TriageOutput reports the triage result for one finding.
type TriageOutput struct {
	FindingID     string `json:"finding_id"`
	AnalysisState string `json:"analysis_state"`
	GateEffect    string `json:"gate_effect"`
	// EventID is the finding event the write recorded. It is the handle a
	// later undo names. Empty for bulk triage.
	EventID string `json:"event_id,omitempty"`
}

// UndoTriageInput names the analysis event to take back.
type UndoTriageInput struct {
	FindingID string
	EventID   string
	UserID    string
}

// BulkTriageInput applies one analysis state to many findings.
type BulkTriageInput struct {
	FindingIDs        []string
	AnalysisState     string
	Reason            string
	AnalysisExpiresAt *time.Time
	UserID            string
}

// GateStatusOutput is a project's gate evaluation for the API.
type GateStatusOutput struct {
	ThresholdBreached bool     `json:"threshold_breached"`
	BlockingCount     int64    `json:"blocking_count"`
	BlockedBy         []string `json:"blocked_by,omitempty"`
	// BlockedByReachability maps each blocked finding id to its latest
	// reachability state. Callers can explain why each finding blocks the gate.
	BlockedByReachability map[string]string `json:"blocked_by_reachability,omitempty"`
	WaivedCount           int               `json:"waived_count,omitempty"`
	// WaivedFindingIDs lists the blocking findings an active waiver covers.
	// It is always present (an empty array when nothing is waived) so a UI
	// can mark each finding as waived without a second round trip.
	WaivedFindingIDs []string `json:"waived_finding_ids"`
	// Policy is the project's effective policy with provenance: which
	// baseline and overrides produced this verdict.
	Policy *PolicyEffectiveResponse `json:"policy,omitempty"`
}

// stateRequiresReason delegates to the canonical lifecycle vocabulary. The
// helpers remain so callers carrying untyped strings (HTTP bodies) validate
// at the boundary before persisting.
func stateRequiresReason(s string) bool {
	st, ok := finding.ParseAnalysisState(s)
	if !ok {
		return false
	}
	return finding.RequiresReason(st)
}

func stateRequiresExpiry(s string) bool {
	st, ok := finding.ParseAnalysisState(s)
	if !ok {
		return false
	}
	return finding.RequiresExpiry(st)
}

func stateToGateEffect(s string) string {
	st, ok := finding.ParseAnalysisState(s)
	if !ok {
		return string(finding.EffectBlock)
	}
	return string(finding.GateEffectFor(st))
}

func (u *Usecases) TriageFinding(ctx context.Context, input TriageInput) (*TriageOutput, error) {
	findingID, err := uuid.Parse(input.FindingID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFindingID, err)
	}
	userID, err := uuid.Parse(input.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}

	if !finding.ValidateAnalysisState(input.AnalysisState) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidState, input.AnalysisState)
	}
	if len(input.Reason) > MaxTriageReasonBytes {
		return nil, fmt.Errorf("%w: at most %d bytes", ErrReasonTooLong, MaxTriageReasonBytes)
	}

	f, err := u.findingWithProjectEditor(ctx, findingID)
	if err != nil {
		return nil, err
	}

	if stateRequiresReason(input.AnalysisState) && input.Reason == "" {
		return nil, ErrReasonRequired
	}
	if err := validateAnalysisExpiry(input.AnalysisState, input.AnalysisExpiresAt, u.clock()); err != nil {
		return nil, err
	}

	gateEffect := stateToGateEffect(input.AnalysisState)
	userIDStr := userID.String()

	if input.ExpectedState != "" && input.ExpectedState != f.AnalysisState {
		return nil, ErrAnalysisConflict
	}

	oldState := f.AnalysisState
	changes, _ := json.Marshal(map[string]any{
		"from":   oldState,
		"to":     input.AnalysisState,
		"reason": input.Reason,
		"before": snapshotOf(f),
	})
	// The write is conditional on the state just read, so the event's from
	// and before snapshot describe what the update replaced.
	updated, created, err := u.deps.Stores.Findings.UpdateAnalysisWithEvent(ctx, port.UpdateAnalysisInput{
		ID:                findingID.String(),
		AnalysisState:     input.AnalysisState,
		GateEffect:        gateEffect,
		AnalysisExpiresAt: input.AnalysisExpiresAt,
		AnalysisReason:    stringPtr(input.Reason),
		AnalysisSource:    "manual",
		ManualOverride:    true,
		ReviewRequired:    false,
		AnalysisUpdatedBy: &userIDStr,
		ExpectedState:     stringPtr(f.AnalysisState),
	}, port.FindingEventInput{
		FindingID: findingID.String(), UserID: &userIDStr, EventType: "analysis_changed",
		OldValue: stringPtr(f.AnalysisState), NewValue: stringPtr(input.AnalysisState), Comment: stringPtr(input.Reason), Changes: changes,
	})
	if err != nil {
		return nil, fmt.Errorf("update analysis and log event: %w", err)
	}

	return &TriageOutput{
		FindingID:     updated.ID,
		AnalysisState: updated.AnalysisState,
		GateEffect:    updated.GateEffect,
		EventID:       created.ID,
	}, nil
}

// analysisSnapshot is the analysis part of a finding as it stood before a
// triage write. Triage events carry it under changes.before so an undo can
// put every field back, including the ones a manual write overwrites
// (source, manual override, review flag).
type analysisSnapshot struct {
	AnalysisState     string     `json:"analysis_state"`
	AnalysisReason    *string    `json:"analysis_reason"`
	AnalysisExpiresAt *time.Time `json:"analysis_expires_at"`
	AnalysisSource    string     `json:"analysis_source"`
	ManualOverride    bool       `json:"manual_override"`
	ReviewRequired    bool       `json:"review_required"`
}

func snapshotOf(f port.Finding) analysisSnapshot {
	return analysisSnapshot{
		AnalysisState:     f.AnalysisState,
		AnalysisReason:    f.AnalysisReason,
		AnalysisExpiresAt: f.AnalysisExpiresAt,
		AnalysisSource:    f.AnalysisSource,
		ManualOverride:    f.ManualOverride,
		ReviewRequired:    f.ReviewRequired,
	}
}

// UndoTriage puts a finding's analysis back to what it was before the named
// event. The event must be the finding's newest analysis event and the
// finding must still be in the state that event set, so an undo can only
// take back the latest change and never overwrite someone else's later one.
// The undo is a new analysis_changed event that names the one it reverses;
// the original stays in the history.
func (u *Usecases) UndoTriage(ctx context.Context, input UndoTriageInput) (*TriageOutput, error) {
	findingID, err := uuid.Parse(input.FindingID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFindingID, err)
	}
	eventID, err := uuid.Parse(input.EventID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidEventID, err)
	}
	userID, err := uuid.Parse(input.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}
	if _, err := u.findingWithProjectEditor(ctx, findingID); err != nil {
		return nil, err
	}

	userIDStr := userID.String()
	updated, created, err := u.deps.Stores.Findings.UndoAnalysis(ctx, findingID.String(),
		func(current port.Finding, newest *port.FindingEvent) (port.UpdateAnalysisInput, port.FindingEventInput, error) {
			return planUndo(current, newest, eventID.String(), userIDStr, time.Now())
		})
	if err != nil {
		if errors.Is(err, port.ErrNotFound) {
			return nil, ErrFindingNotFound
		}
		return nil, fmt.Errorf("undo analysis: %w", err)
	}
	return &TriageOutput{
		FindingID:     updated.ID,
		AnalysisState: updated.AnalysisState,
		GateEffect:    updated.GateEffect,
		EventID:       created.ID,
	}, nil
}

// planUndo checks that eventID may be undone against the locked finding and
// builds the write that restores the event's before snapshot.
func planUndo(current port.Finding, newest *port.FindingEvent, eventID, userID string, now time.Time) (port.UpdateAnalysisInput, port.FindingEventInput, error) {
	var none port.UpdateAnalysisInput
	if newest == nil || newest.ID != eventID {
		return none, port.FindingEventInput{}, ErrAnalysisConflict
	}
	if newest.EventType != "analysis_changed" {
		return none, port.FindingEventInput{}, ErrUndoUnavailable
	}
	var changes struct {
		To     string            `json:"to"`
		Before *analysisSnapshot `json:"before"`
	}
	if err := json.Unmarshal(newest.Changes, &changes); err != nil || changes.Before == nil || changes.To == "" {
		return none, port.FindingEventInput{}, ErrUndoUnavailable
	}
	before := *changes.Before
	if !finding.ValidateAnalysisState(before.AnalysisState) {
		return none, port.FindingEventInput{}, ErrUndoUnavailable
	}
	if current.AnalysisState != changes.To {
		return none, port.FindingEventInput{}, ErrAnalysisConflict
	}
	if before.AnalysisExpiresAt != nil && !before.AnalysisExpiresAt.After(now) {
		return none, port.FindingEventInput{}, ErrPreviousExpiryPassed
	}

	reason := ""
	if before.AnalysisReason != nil {
		reason = *before.AnalysisReason
	}
	changesJSON, _ := json.Marshal(map[string]any{
		"from":    current.AnalysisState,
		"to":      before.AnalysisState,
		"reason":  reason,
		"undo_of": eventID,
		"before":  snapshotOf(current),
	})
	return port.UpdateAnalysisInput{
			AnalysisState:     before.AnalysisState,
			GateEffect:        stateToGateEffect(before.AnalysisState),
			AnalysisExpiresAt: before.AnalysisExpiresAt,
			AnalysisReason:    before.AnalysisReason,
			AnalysisSource:    before.AnalysisSource,
			ManualOverride:    before.ManualOverride,
			ReviewRequired:    before.ReviewRequired,
			AnalysisUpdatedBy: &userID,
		}, port.FindingEventInput{
			UserID:    &userID,
			EventType: "analysis_changed",
			OldValue:  stringPtr(current.AnalysisState),
			NewValue:  stringPtr(before.AnalysisState),
			Changes:   changesJSON,
		}, nil
}

func (u *Usecases) BulkTriage(ctx context.Context, input BulkTriageInput) ([]TriageOutput, error) {
	userID, err := uuid.Parse(input.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}
	if err := validateBulkTriage(input); err != nil {
		return nil, err
	}
	// The lookup returns one row per distinct id, so a repeated id (or the
	// same UUID in another case) must collapse before the count check and
	// before it inflates the event's count.
	input.FindingIDs = distinctUUIDs(input.FindingIDs)

	findings, err := u.deps.Stores.Findings.ListByIDs(ctx, input.FindingIDs)
	if err != nil {
		return nil, fmt.Errorf("lookup findings: %w", err)
	}
	if len(findings) != len(input.FindingIDs) {
		return nil, fmt.Errorf("%w: one or more findings not found", ErrFindingNotFound)
	}
	if err := u.checkFindingRowsProjectEditor(ctx, findings); err != nil {
		return nil, err
	}
	if err := validateBulkTriageRequirements(input, findings, u.clock()); err != nil {
		return nil, err
	}

	gateEffect := stateToGateEffect(input.AnalysisState)
	userIDStr := userID.String()

	changes, _ := json.Marshal(map[string]any{
		"to":     input.AnalysisState,
		"reason": input.Reason,
		"count":  len(input.FindingIDs),
	})
	updated, err := u.deps.Stores.Findings.BulkTriage(ctx, port.UpdateAnalysisInput{
		AnalysisState:     input.AnalysisState,
		GateEffect:        gateEffect,
		AnalysisExpiresAt: input.AnalysisExpiresAt,
		AnalysisReason:    stringPtr(input.Reason),
		AnalysisSource:    "bulk",
		ManualOverride:    true,
		ReviewRequired:    false,
		AnalysisUpdatedBy: &userIDStr,
	}, input.FindingIDs, port.FindingEventInput{
		UserID:    &userIDStr,
		EventType: "bulk_triage_applied",
		NewValue:  stringPtr(input.AnalysisState),
		Changes:   changes,
	})
	if err != nil {
		return nil, fmt.Errorf("bulk triage: %w", err)
	}

	results := make([]TriageOutput, len(updated))
	for i, f := range updated {
		results[i] = TriageOutput{
			FindingID:     f.ID,
			AnalysisState: f.AnalysisState,
			GateEffect:    f.GateEffect,
		}
	}
	return results, nil
}

// distinctUUIDs returns ids in canonical form, first occurrence kept, in
// order. The caller has already checked that every id parses.
func distinctUUIDs(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		canonical := uuid.MustParse(id).String()
		if seen[canonical] {
			continue
		}
		seen[canonical] = true
		out = append(out, canonical)
	}
	return out
}

// validateBulkTriage checks the analysis state and finding-ID list before
// any lookup, then the per-finding reason/expiry requirements after.
func validateBulkTriage(input BulkTriageInput) error {
	if !finding.ValidateAnalysisState(input.AnalysisState) {
		return fmt.Errorf("%w: %q", ErrInvalidState, input.AnalysisState)
	}
	if len(input.FindingIDs) > MaxBulkTriageFindings {
		return fmt.Errorf("%w: at most %d", ErrTooManyFindings, MaxBulkTriageFindings)
	}
	if len(input.Reason) > MaxTriageReasonBytes {
		return fmt.Errorf("%w: at most %d bytes", ErrReasonTooLong, MaxTriageReasonBytes)
	}
	for _, id := range input.FindingIDs {
		if _, err := uuid.Parse(id); err != nil {
			return fmt.Errorf("%w: %q", ErrInvalidFindingID, id)
		}
	}
	return nil
}

// validateBulkTriageRequirements enforces reason/expiry rules per finding.
func validateBulkTriageRequirements(input BulkTriageInput, findings []port.Finding, now time.Time) error {
	if err := validateAnalysisExpiry(input.AnalysisState, input.AnalysisExpiresAt, now); err != nil {
		return err
	}
	for _, f := range findings {
		if stateRequiresReason(input.AnalysisState) && input.Reason == "" {
			return fmt.Errorf("finding %s: %w", f.ID, ErrReasonRequired)
		}
	}
	return nil
}

func validateAnalysisExpiry(state string, expiry *time.Time, now time.Time) error {
	if expiry == nil {
		if stateRequiresExpiry(state) {
			return ErrExpiryRequired
		}
		return nil
	}
	if !expiry.After(now) {
		return ErrExpiryPassed
	}
	return nil
}

// gatePoliciesForMode translates a watcher gate mode from the effective
// policy ('immediate' | 'off' | 'require_triage') into gate source policies.
// The source category is the watcher finding kind (cve_watcher), supplied by
// the watcher registration — the gate core itself never hard-codes that
// literal. The effective policy is the only source of the mode.
func gatePoliciesForMode(mode string) []gate.GatePolicy {
	switch mode {
	case gate.PolicyOff, gate.PolicyRequireTriage:
		return []gate.GatePolicy{{Source: "cve_watcher", Mode: mode}}
	default:
		return nil // immediate: watcher findings gate like any other
	}
}

// evaluateProjectGate runs the gate the way the gate endpoint does: the
// project policy sets the floor (a positive requested rank can only tighten
// it, zero means no explicit severity) and the watcher admission policies apply.
// The statistics take their blocking numbers from the same call, so the two
// cannot disagree.
func (u *Usecases) evaluateProjectGate(ctx context.Context, project port.Project, minSeverityRank int16) (gate.Decision, *PolicyEffectiveResponse, error) {
	floor, policy, err := u.gateFloor(ctx, project, minSeverityRank)
	if err != nil {
		return gate.Decision{}, policy, fmt.Errorf("resolve policy: %w", err)
	}
	u.initGate()
	decision, err := u.gate.EvaluateWithPolicies(ctx, project.ID, floor, gatePoliciesForMode(policy.WatcherGate))
	if err != nil {
		return gate.Decision{}, policy, fmt.Errorf("gate eval: %w", err)
	}
	return decision, policy, nil
}

func (u *Usecases) GetGateStatus(ctx context.Context, projectSlug string, minSeverityRank int16) (*GateStatusOutput, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectMember(ctx, project.ID); err != nil {
		return nil, err
	}

	decision, policy, err := u.evaluateProjectGate(ctx, project, minSeverityRank)
	if err != nil {
		return nil, err
	}

	reachability := make(map[string]string, len(decision.BlockedByReachability))
	for id, state := range decision.BlockedByReachability {
		reachability[id] = string(state)
	}

	return &GateStatusOutput{
		ThresholdBreached:     decision.Status == gate.StatusFail,
		BlockingCount:         int64(decision.TotalBlocking - decision.WaivedCount),
		BlockedBy:             decision.BlockedBy,
		BlockedByReachability: reachability,
		WaivedCount:           decision.WaivedCount,
		WaivedFindingIDs:      decision.WaivedFindingIDs,
		Policy:                policy,
	}, nil
}

// GetIntroducedGateStatus evaluates the gate over findings one report
// introduced: change-scoped CI feedback that targets new risk
// while the full gate keeps covering existing debt. The report must belong
// to the project in the URL; a missing and a foreign report are refused with
// the same error so report ids cannot be probed. An empty reportID matches
// nothing and passes.
func (u *Usecases) GetIntroducedGateStatus(ctx context.Context, projectSlug string, minSeverityRank int16, reportID string) (*GateStatusOutput, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectMember(ctx, project.ID); err != nil {
		return nil, err
	}

	if reportID != "" {
		// The report is the scope of the evaluation, so it must live in the
		// authorized project. A missing report answers exactly like a foreign
		// one (ErrProjectAccessDenied, which the handler maps to 403
		// project_access_denied, the same answer pr-check gives) so a caller
		// cannot tell "not yours" from "does not exist".
		if _, err := u.requireReportInProject(ctx, project.ID, reportID); err != nil {
			return nil, err
		}
	}

	// The project policy sets the floor; a positive requested rank can only
	// tighten it. Zero means no explicit severity.
	floor, policy, err := u.gateFloor(ctx, project, minSeverityRank)
	if err != nil {
		return nil, fmt.Errorf("resolve policy: %w", err)
	}

	u.initGate()
	decision, err := u.gate.EvaluateIntroducedOnly(ctx, project.ID, floor, reportID, gatePoliciesForMode(policy.WatcherGate))
	if err != nil {
		return nil, fmt.Errorf("gate eval: %w", err)
	}

	reachability := make(map[string]string, len(decision.BlockedByReachability))
	for id, state := range decision.BlockedByReachability {
		reachability[id] = string(state)
	}

	return &GateStatusOutput{
		ThresholdBreached:     decision.Status == gate.StatusFail,
		BlockingCount:         int64(decision.TotalBlocking - decision.WaivedCount),
		BlockedBy:             decision.BlockedBy,
		BlockedByReachability: reachability,
		WaivedCount:           decision.WaivedCount,
		WaivedFindingIDs:      decision.WaivedFindingIDs,
		Policy:                policy,
	}, nil
}

func (u *Usecases) GetFindingEvents(ctx context.Context, findingID string, eventTypes []string, limit, offset int32) ([]FindingEvent, error) {
	fID, err := uuid.Parse(findingID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidFindingID, err)
	}
	if err := u.checkFindingProjectAccess(ctx, fID); err != nil {
		return nil, err
	}

	events, err := u.deps.Stores.Findings.ListEvents(ctx, fID.String(), eventTypes, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}

	result := make([]FindingEvent, len(events))
	actors := make([]string, 0, len(events))
	for _, e := range events {
		actors = append(actors, derefStr(e.UserID))
	}
	labels := u.peopleLabels(ctx, actors)
	for i, e := range events {
		result[i] = FindingEvent{
			UserName:  labels[derefStr(e.UserID)],
			ID:        e.ID,
			FindingID: e.FindingID,
			UserID:    derefStr(e.UserID),
			EventType: e.EventType,
			Changes:   e.Changes,
			CreatedAt: e.CreatedAt,
			OldValue:  e.OldValue,
			NewValue:  e.NewValue,
			Comment:   e.Comment,
		}
	}
	return result, nil
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
