package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/xMinhx/specht/internal/finding"
	"github.com/xMinhx/specht/internal/gate"
	"github.com/xMinhx/specht/internal/port"
)

var (
	ErrFindingNotFound = errors.New("finding not found")
	ErrReasonRequired  = errors.New("reason is required for this analysis state")
	ErrExpiryRequired  = errors.New("expiry is required for accepted_risk and wont_fix")
	ErrInvalidState    = errors.New("invalid analysis state")
)

// TriageInput sets a finding's analysis state with an optional reason and expiry.
type TriageInput struct {
	FindingID         string
	AnalysisState     string
	Reason            string
	AnalysisExpiresAt *time.Time
	UserID            string
}

// TriageOutput reports the triage result for one finding.
type TriageOutput struct {
	FindingID     string `json:"finding_id"`
	AnalysisState string `json:"analysis_state"`
	GateEffect    string `json:"gate_effect"`
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
	// Policy is the project's effective policy with provenance: which
	// baseline and overrides produced this verdict (SOLO-185).
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
		return nil, fmt.Errorf("invalid finding id: %w", err)
	}
	userID, err := uuid.Parse(input.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}

	if !finding.ValidateAnalysisState(input.AnalysisState) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidState, input.AnalysisState)
	}

	f, err := u.findingWithProjectAccess(ctx, findingID)
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

	updated, err := u.deps.Stores.Findings.UpdateAnalysis(ctx, port.UpdateAnalysisInput{
		ID:                findingID.String(),
		AnalysisState:     input.AnalysisState,
		GateEffect:        gateEffect,
		AnalysisExpiresAt: input.AnalysisExpiresAt,
		AnalysisReason:    stringPtr(input.Reason),
		AnalysisSource:    "manual",
		ManualOverride:    true,
		ReviewRequired:    false,
		AnalysisUpdatedBy: &userIDStr,
	})
	if err != nil {
		return nil, fmt.Errorf("update analysis: %w", err)
	}

	oldState := f.AnalysisState
	changes, _ := json.Marshal(map[string]any{
		"from":   oldState,
		"to":     input.AnalysisState,
		"reason": input.Reason,
	})
	_, err = u.deps.Stores.Findings.CreateEvent(ctx, port.FindingEventInput{
		FindingID: findingID.String(),
		UserID:    &userIDStr,
		EventType: "analysis_changed",
		OldValue:  stringPtr(oldState),
		NewValue:  stringPtr(input.AnalysisState),
		Comment:   stringPtr(input.Reason),
		Changes:   changes,
	})
	if err != nil {
		return nil, fmt.Errorf("log triage event: %w", err)
	}

	return &TriageOutput{
		FindingID:     updated.ID,
		AnalysisState: updated.AnalysisState,
		GateEffect:    updated.GateEffect,
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

	findings, err := u.deps.Stores.Findings.ListByIDs(ctx, input.FindingIDs)
	if err != nil {
		return nil, fmt.Errorf("lookup findings: %w", err)
	}
	if len(findings) != len(input.FindingIDs) {
		return nil, fmt.Errorf("%w: one or more findings not found", ErrFindingNotFound)
	}
	if err := u.checkFindingRowsProjectAccess(ctx, findings); err != nil {
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
	for _, id := range input.FindingIDs {
		if _, err := uuid.Parse(id); err != nil {
			return fmt.Errorf("invalid finding id %q: %w", id, err)
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

// gatePoliciesForProject translates a project's stored cve_watcher_gate mode
// into gate source policies. The mode names match the DB column
// ('immediate' | 'off' | 'require_triage'); the source category is the
// watcher finding kind (cve_watcher), supplied by the watcher registration —
// the gate core itself never hard-codes that literal.
func gatePoliciesForProject(p port.Project) []gate.GatePolicy {
	if p.CveWatcherGate == "" || p.CveWatcherGate == "immediate" {
		return nil // default: watcher findings gate immediately
	}
	mode := p.CveWatcherGate
	switch mode {
	case gate.PolicyOff, gate.PolicyRequireTriage:
		return []gate.GatePolicy{{Source: "cve_watcher", Mode: mode}}
	default:
		return nil
	}
}

func (u *Usecases) GetGateStatus(ctx context.Context, projectSlug string, minSeverityRank int16) (*GateStatusOutput, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}

	// A non-positive floor means "no explicit severity": the project's
	// effective policy decides. An explicit floor always wins.
	floor := minSeverityRank
	if floor <= 0 {
		floor = u.effectiveSeverityFloor(ctx, project, nil)
	}

	u.initGate()
	decision, err := u.gate.EvaluateWithPolicies(ctx, project.ID, floor, gatePoliciesForProject(project))
	if err != nil {
		return nil, fmt.Errorf("gate eval: %w", err)
	}

	reachability := make(map[string]string, len(decision.BlockedByReachability))
	for id, state := range decision.BlockedByReachability {
		reachability[id] = string(state)
	}

	policy, err := u.effectivePolicy(ctx, project)
	if err != nil {
		return nil, fmt.Errorf("resolve policy: %w", err)
	}

	return &GateStatusOutput{
		ThresholdBreached:     decision.Status == gate.StatusFail,
		BlockingCount:         int64(decision.TotalBlocking - decision.WaivedCount),
		BlockedBy:             decision.BlockedBy,
		BlockedByReachability: reachability,
		WaivedCount:           decision.WaivedCount,
		Policy:                policy,
	}, nil
}

// GetIntroducedGateStatus evaluates the gate over findings one report
// introduced (SOLO-184): change-scoped CI feedback that targets new risk
// while the full gate keeps covering existing debt. An empty reportID
// matches nothing and passes.
func (u *Usecases) GetIntroducedGateStatus(ctx context.Context, projectSlug string, minSeverityRank int16, reportID string) (*GateStatusOutput, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}

	u.initGate()
	decision, err := u.gate.EvaluateIntroducedOnly(ctx, project.ID, minSeverityRank, reportID, gatePoliciesForProject(project))
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
	for i, e := range events {
		result[i] = FindingEvent{
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
