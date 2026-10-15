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
	ErrInvalidState    = errors.New("invalid analysis state")
	ErrTooManyFindings = errors.New("too many findings in one request")
	ErrReasonTooLong   = errors.New("reason is too long")
	// ErrAnalysisConflict means the finding no longer matches the state the
	// caller based its write on (a stale expected_state, or an undo of an
	// event that is not the newest analysis event).
	ErrAnalysisConflict = port.ErrAnalysisConflict
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
	if stateRequiresExpiry(input.AnalysisState) && input.AnalysisExpiresAt == nil {
		return nil, ErrExpiryRequired
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

func (u *Usecases) BulkTriage(ctx context.Context, input BulkTriageInput) ([]TriageOutput, error) {
	userID, err := uuid.Parse(input.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}
	if err := validateBulkTriage(input); err != nil {
		return nil, err
	}

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
	if err := validateBulkTriageRequirements(input, findings); err != nil {
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
func validateBulkTriageRequirements(input BulkTriageInput, findings []port.Finding) error {
	for _, f := range findings {
		if stateRequiresReason(input.AnalysisState) && input.Reason == "" {
			return fmt.Errorf("finding %s: %w", f.ID, ErrReasonRequired)
		}
		if stateRequiresExpiry(input.AnalysisState) && input.AnalysisExpiresAt == nil {
			return fmt.Errorf("finding %s: %w", f.ID, ErrExpiryRequired)
		}
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
// while the full gate keeps covering existing debt. An empty reportID
// matches nothing and passes.
func (u *Usecases) GetIntroducedGateStatus(ctx context.Context, projectSlug string, minSeverityRank int16, reportID string) (*GateStatusOutput, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectMember(ctx, project.ID); err != nil {
		return nil, err
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
		return nil, fmt.Errorf("invalid finding id: %w", err)
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
