package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/xMinhx/specht/internal/finding"
	"github.com/xMinhx/specht/internal/gate"
	"github.com/xMinhx/specht/internal/repo"
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

	finding, err := u.findingWithProjectAccess(ctx, findingID)
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

	var expiresAt pgtype.Timestamptz
	if input.AnalysisExpiresAt != nil {
		expiresAt = pgtype.Timestamptz{Time: *input.AnalysisExpiresAt, Valid: true}
	}

	updated, err := u.deps.Repos.Findings.UpdateAnalysis(ctx, repo.UpdateAnalysisParams{
		ID:                pgtype.UUID{Bytes: findingID, Valid: true},
		AnalysisState:     input.AnalysisState,
		GateEffect:        gateEffect,
		AnalysisExpiresAt: expiresAt,
		AnalysisReason:    pgtype.Text{String: input.Reason, Valid: input.Reason != ""},
		AnalysisSource:    "manual",
		ManualOverride:    true,
		ReviewRequired:    false,
		AnalysisUpdatedBy: pgtype.UUID{Bytes: userID, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("update analysis: %w", err)
	}

	oldState := finding.AnalysisState
	changes, _ := json.Marshal(map[string]any{
		"from":   oldState,
		"to":     input.AnalysisState,
		"reason": input.Reason,
	})
	_, err = u.deps.Repos.Findings.CreateEvent(ctx, repo.CreateEventParams{
		FindingID: pgtype.UUID{Bytes: findingID, Valid: true},
		UserID:    pgtype.UUID{Bytes: userID, Valid: true},
		EventType: "analysis_changed",
		OldValue:  pgtype.Text{String: oldState, Valid: true},
		NewValue:  pgtype.Text{String: input.AnalysisState, Valid: true},
		Comment:   pgtype.Text{String: input.Reason, Valid: input.Reason != ""},
		Changes:   changes,
	})
	if err != nil {
		return nil, fmt.Errorf("log triage event: %w", err)
	}

	return &TriageOutput{
		FindingID:     uuid.UUID(updated.ID.Bytes).String(),
		AnalysisState: updated.AnalysisState,
		GateEffect:    updated.GateEffect,
	}, nil
}

func (u *Usecases) BulkTriage(ctx context.Context, input BulkTriageInput) ([]TriageOutput, error) {
	userID, err := uuid.Parse(input.UserID)
	if err != nil {
		return nil, fmt.Errorf("invalid user id: %w", err)
	}

	if !finding.ValidateAnalysisState(input.AnalysisState) {
		return nil, fmt.Errorf("%w: %q", ErrInvalidState, input.AnalysisState)
	}

	findingIDs := make([]pgtype.UUID, len(input.FindingIDs))
	for i, id := range input.FindingIDs {
		parsed, err := uuid.Parse(id)
		if err != nil {
			return nil, fmt.Errorf("invalid finding id %q: %w", id, err)
		}
		findingIDs[i] = pgtype.UUID{Bytes: parsed, Valid: true}
	}

	findings, err := u.deps.Repos.Findings.ListByIDs(ctx, findingIDs)
	if err != nil {
		return nil, fmt.Errorf("lookup findings: %w", err)
	}
	if len(findings) != len(input.FindingIDs) {
		return nil, fmt.Errorf("%w: one or more findings not found", ErrFindingNotFound)
	}
	if err := checkFindingRowsProjectAccess(ctx, findings); err != nil {
		return nil, err
	}

	for _, f := range findings {
		if stateRequiresReason(input.AnalysisState) && input.Reason == "" {
			return nil, fmt.Errorf("finding %s: %w", uuid.UUID(f.ID.Bytes).String(), ErrReasonRequired)
		}
		if stateRequiresExpiry(input.AnalysisState) && input.AnalysisExpiresAt == nil {
			return nil, fmt.Errorf("finding %s: %w", uuid.UUID(f.ID.Bytes).String(), ErrExpiryRequired)
		}
	}

	gateEffect := stateToGateEffect(input.AnalysisState)

	var expiresAt pgtype.Timestamptz
	if input.AnalysisExpiresAt != nil {
		expiresAt = pgtype.Timestamptz{Time: *input.AnalysisExpiresAt, Valid: true}
	}

	updated, err := u.deps.Repos.Findings.BulkUpdateAnalysis(ctx, repo.BulkUpdateAnalysisParams{
		IDs:               findingIDs,
		AnalysisState:     input.AnalysisState,
		GateEffect:        gateEffect,
		AnalysisExpiresAt: expiresAt,
		AnalysisReason:    pgtype.Text{String: input.Reason, Valid: input.Reason != ""},
		AnalysisSource:    "bulk",
		ManualOverride:    true,
		ReviewRequired:    false,
		AnalysisUpdatedBy: pgtype.UUID{Bytes: userID, Valid: true},
	})
	if err != nil {
		return nil, fmt.Errorf("bulk update analysis: %w", err)
	}

	changes, _ := json.Marshal(map[string]any{
		"to":     input.AnalysisState,
		"reason": input.Reason,
		"count":  len(updated),
	})
	for _, f := range updated {
		_, err = u.deps.Repos.Findings.CreateEvent(ctx, repo.CreateEventParams{
			FindingID: f.ID,
			UserID:    pgtype.UUID{Bytes: userID, Valid: true},
			EventType: "bulk_triage_applied",
			NewValue:  pgtype.Text{String: input.AnalysisState, Valid: true},
			Changes:   changes,
		})
		if err != nil {
			return nil, fmt.Errorf("log bulk event: %w", err)
		}
	}

	results := make([]TriageOutput, len(updated))
	for i, f := range updated {
		results[i] = TriageOutput{
			FindingID:     uuid.UUID(f.ID.Bytes).String(),
			AnalysisState: f.AnalysisState,
			GateEffect:    f.GateEffect,
		}
	}
	return results, nil
}

func (u *Usecases) GetGateStatus(ctx context.Context, projectSlug string, minSeverityRank int16) (*GateStatusOutput, error) {
	project, err := u.deps.Repos.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf("lookup project %q: %w", projectSlug, err)
	}

	u.initGate()
	projectID := uuid.UUID(project.ID.Bytes).String()
	decision, err := u.gate.Evaluate(ctx, projectID, minSeverityRank)
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

	events, err := u.deps.Repos.Findings.ListEvents(ctx, pgtype.UUID{Bytes: fID, Valid: true}, eventTypes, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}

	result := make([]FindingEvent, len(events))
	for i, e := range events {
		result[i] = FindingEvent{
			ID:        uuidStr(e.ID),
			FindingID: uuidStr(e.FindingID),
			UserID:    uuidStr(e.UserID),
			EventType: e.EventType,
			Changes:   e.Changes,
			CreatedAt: e.CreatedAt.Time,
		}
		if e.OldValue.Valid {
			v := e.OldValue.String
			result[i].OldValue = &v
		}
		if e.NewValue.Valid {
			v := e.NewValue.String
			result[i].NewValue = &v
		}
		if e.Comment.Valid {
			v := e.Comment.String
			result[i].Comment = &v
		}
	}
	return result, nil
}
