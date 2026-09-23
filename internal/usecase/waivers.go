package usecase

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/minh-tg/specht/internal/gate"
	"github.com/minh-tg/specht/internal/port"
)

// errInvalidWaiverIDFormat wraps waiver-id parse failures.
const errInvalidWaiverIDFormat = "invalid waiver id: %w"

// WaiverResponse is the API representation of a waiver with its condition,
// context, and target rows attached.
type WaiverResponse struct {
	ID          string                    `json:"id"`
	ProjectID   string                    `json:"project_id"`
	Name        string                    `json:"name"`
	Description string                    `json:"description"`
	Enabled     bool                      `json:"enabled"`
	Conditions  []WaiverConditionResp     `json:"conditions"`
	Contexts    []WaiverContextResp       `json:"contexts"`
	Targets     []WaiverFindingTargetResp `json:"targets"`
	CreatedAt   string                    `json:"created_at"`
	UpdatedAt   string                    `json:"updated_at"`
}

// WaiverConditionResp is a waiver condition in API responses.
type WaiverConditionResp struct {
	ID       string `json:"id"`
	Field    string `json:"field"`
	Operator string `json:"operator"`
	Value    string `json:"value"`
}

// WaiverContextResp is a waiver context scope in API responses.
type WaiverContextResp struct {
	ID            string `json:"id"`
	EnvironmentID string `json:"environment_id,omitempty"`
	TargetID      string `json:"target_id,omitempty"`
	ArtifactID    string `json:"artifact_id,omitempty"`
}

// WaiverFindingTargetResp is a waiver finding target in API responses.
type WaiverFindingTargetResp struct {
	ID        string `json:"id"`
	FindingID string `json:"finding_id"`
}

// WaiverEventResp is a waiver audit event in API responses.
type WaiverEventResp struct {
	ID        string          `json:"id"`
	WaiverID  string          `json:"waiver_id"`
	EventType string          `json:"event_type"`
	ActorID   string          `json:"actor_id,omitempty"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt string          `json:"created_at"`
}

// CreateWaiverInput is a request to create a waiver: a name/description plus
// optional conditions, deployment-context scopes, and directly-targeted
// finding ids. An empty Conditions/Contexts/Targets set makes the waiver
// apply to every blocking finding in the project.
type CreateWaiverInput struct {
	ProjectSlug string
	Name        string
	Description string
	Conditions  []CreateWaiverConditionInput
	Contexts    []CreateWaiverContextInput
	TargetIDs   []string
	ActorID     string
}

// CreateWaiverConditionInput is a condition input for waiver create/update.
type CreateWaiverConditionInput struct {
	Field    string
	Operator string
	Value    string
}

// CreateWaiverContextInput is a context scope input for waiver create/update.
type CreateWaiverContextInput struct {
	EnvironmentID string
	TargetID      string
	ArtifactID    string
}

// UpdateWaiverInput is a request to update a waiver. Name and Description
// replace the stored values when non-empty; a non-nil Conditions/Contexts/
// TargetIDs slice replaces that child set (nil leaves it untouched).
type UpdateWaiverInput struct {
	WaiverID    string
	ProjectSlug string
	Name        string
	Description string
	Conditions  []CreateWaiverConditionInput
	Contexts    []CreateWaiverContextInput
	TargetIDs   []string
	ActorID     string
}

// WaiverDetailResponse is a waiver with full condition/context/target rows.
type WaiverDetailResponse struct {
	WaiverResponse
	Conditions []WaiverConditionResp     `json:"conditions"`
	Contexts   []WaiverContextResp       `json:"contexts"`
	Targets    []WaiverFindingTargetResp `json:"targets"`
}

func toWaiver(w port.Waiver) WaiverResponse {
	return WaiverResponse{
		ID:          w.ID,
		ProjectID:   w.ProjectID,
		Name:        w.Name,
		Description: w.Description,
		Enabled:     w.Enabled,
		Conditions:  make([]WaiverConditionResp, 0),
		Contexts:    make([]WaiverContextResp, 0),
		Targets:     make([]WaiverFindingTargetResp, 0),
		CreatedAt:   w.CreatedAt.Format(time.RFC3339),
		UpdatedAt:   w.UpdatedAt.Format(time.RFC3339),
	}
}

func toWaiverCondition(c port.WaiverCondition) WaiverConditionResp {
	return WaiverConditionResp{
		ID:       c.ID,
		Field:    c.Field,
		Operator: c.Operator,
		Value:    c.Value,
	}
}

func toWaiverContext(c port.WaiverContext) WaiverContextResp {
	return WaiverContextResp{
		ID:            c.ID,
		EnvironmentID: c.EnvironmentID,
		TargetID:      c.TargetID,
		ArtifactID:    c.ArtifactID,
	}
}

func toWaiverFindingTarget(t port.WaiverFindingTarget) WaiverFindingTargetResp {
	return WaiverFindingTargetResp{
		ID:        t.ID,
		FindingID: t.FindingID,
	}
}

func toWaiverEvent(e port.WaiverEvent) WaiverEventResp {
	return WaiverEventResp{
		ID:        e.ID,
		WaiverID:  e.WaiverID,
		EventType: e.EventType,
		ActorID:   e.ActorID,
		Metadata:  e.Metadata,
		CreatedAt: e.CreatedAt.Format(time.RFC3339),
	}
}

func toWaiverDetail(w port.Waiver, conditions []port.WaiverCondition, contexts []port.WaiverContext, targets []port.WaiverFindingTarget) WaiverDetailResponse {
	resp := WaiverDetailResponse{
		WaiverResponse: toWaiver(w),
		Conditions:     make([]WaiverConditionResp, len(conditions)),
		Contexts:       make([]WaiverContextResp, len(contexts)),
		Targets:        make([]WaiverFindingTargetResp, len(targets)),
	}
	for i, c := range conditions {
		resp.Conditions[i] = toWaiverCondition(c)
	}
	for i, c := range contexts {
		resp.Contexts[i] = toWaiverContext(c)
	}
	for i, t := range targets {
		resp.Targets[i] = toWaiverFindingTarget(t)
	}
	return resp
}

var waiverCreatedEvent = []byte("{}")

func (u *Usecases) CreateWaiver(ctx context.Context, input CreateWaiverInput) (*WaiverResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, input.ProjectSlug, err)
	}
	if err := u.requireProjectAdminForWaiver(ctx, project.ID); err != nil {
		return nil, err
	}

	conditions := make([]port.WaiverCondition, len(input.Conditions))
	for i, c := range input.Conditions {
		conditions[i] = port.WaiverCondition{
			Field:    c.Field,
			Operator: c.Operator,
			Value:    c.Value,
		}
	}

	contexts, err := waiverContextInputs(input.Contexts)
	if err != nil {
		return nil, err
	}

	targets := make([]port.WaiverFindingTarget, len(input.TargetIDs))
	for i, targetID := range input.TargetIDs {
		id, err := uuid.Parse(targetID)
		if err != nil {
			return nil, fmt.Errorf("invalid target finding id %q: %w", targetID, err)
		}
		targets[i] = port.WaiverFindingTarget{FindingID: id.String()}
	}

	actorID := stringPtr(input.ActorID)
	w, err := u.deps.Stores.Waivers.CreateWithDetails(ctx, port.CreateWaiverInput{
		ProjectID:   project.ID,
		Name:        input.Name,
		Description: input.Description,
		Enabled:     true,
		Conditions:  conditions,
		Contexts:    contexts,
		Targets:     targets,
		Event: port.WaiverEventInput{
			EventType: "created",
			ActorID:   actorID,
			Metadata:  waiverCreatedEvent,
		},
	})
	if err != nil {
		return nil, err
	}

	r := toWaiver(w)
	return &r, nil
}

func (u *Usecases) ListWaivers(ctx context.Context, projectSlug string) ([]WaiverResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}

	waivers, err := u.deps.Stores.Waivers.List(ctx, project.ID)
	if err != nil {
		return nil, fmt.Errorf("list waivers: %w", err)
	}

	resp := make([]WaiverResponse, len(waivers))
	for i, w := range waivers {
		resp[i] = toWaiver(w)
	}
	return resp, nil
}

func (u *Usecases) GetWaiver(ctx context.Context, projectSlug, waiverID string) (*WaiverDetailResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return nil, fmt.Errorf(errInvalidWaiverIDFormat, err)
	}

	w, err := u.deps.Stores.Waivers.GetByID(ctx, id.String(), project.ID)
	if err != nil {
		return nil, fmt.Errorf("get waiver: %w", err)
	}

	conditions, err := u.deps.Stores.Waivers.ListConditions(ctx, w.ID)
	if err != nil {
		return nil, fmt.Errorf("list conditions: %w", err)
	}

	contexts, err := u.deps.Stores.Waivers.ListContexts(ctx, w.ID)
	if err != nil {
		return nil, fmt.Errorf("list contexts: %w", err)
	}

	targets, err := u.deps.Stores.Waivers.ListFindingTargets(ctx, w.ID)
	if err != nil {
		return nil, fmt.Errorf("list finding targets: %w", err)
	}

	resp := toWaiverDetail(w, conditions, contexts, targets)
	return &resp, nil
}

func (u *Usecases) UpdateWaiver(ctx context.Context, input UpdateWaiverInput) (*WaiverResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, input.ProjectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, input.ProjectSlug, err)
	}
	if err := u.requireProjectAdminForWaiver(ctx, project.ID); err != nil {
		return nil, err
	}

	id, err := uuid.Parse(input.WaiverID)
	if err != nil {
		return nil, fmt.Errorf(errInvalidWaiverIDFormat, err)
	}
	waiver := port.Waiver{
		ID:          id.String(),
		ProjectID:   project.ID,
		Name:        input.Name,
		Description: input.Description,
	}

	var conditions *[]port.WaiverCondition
	if input.Conditions != nil {
		conds := make([]port.WaiverCondition, len(input.Conditions))
		for i, c := range input.Conditions {
			conds[i] = port.WaiverCondition{Field: c.Field, Operator: c.Operator, Value: c.Value}
		}
		conditions = &conds
	}

	var contexts *[]port.WaiverContext
	if input.Contexts != nil {
		ctxs, err := waiverContextInputs(input.Contexts)
		if err != nil {
			return nil, err
		}
		contexts = &ctxs
	}

	var targets *[]port.WaiverFindingTarget
	if input.TargetIDs != nil {
		tgts := make([]port.WaiverFindingTarget, len(input.TargetIDs))
		for i, targetID := range input.TargetIDs {
			uid, err := uuid.Parse(targetID)
			if err != nil {
				return nil, fmt.Errorf("invalid target finding id %q: %w", targetID, err)
			}
			tgts[i] = port.WaiverFindingTarget{FindingID: uid.String()}
		}
		targets = &tgts
	}

	actorID := stringPtr(input.ActorID)
	w, err := u.deps.Stores.Waivers.UpdateWithDetails(ctx, waiver, conditions, contexts, targets, port.WaiverEventInput{
		EventType: "updated",
		ActorID:   actorID,
		Metadata:  waiverCreatedEvent,
	})
	if err != nil {
		return nil, err
	}

	r := toWaiver(w)
	return &r, nil
}

// waiverContextInputs validates create/update waiver context inputs and
// keeps them as port context DTOs (empty ids are wildcards).
func waiverContextInputs(inputs []CreateWaiverContextInput) ([]port.WaiverContext, error) {
	out := make([]port.WaiverContext, len(inputs))
	for i, c := range inputs {
		envID, err := parseOptionalUUID(c.EnvironmentID, "environment_id")
		if err != nil {
			return nil, err
		}
		targetID, err := parseOptionalUUID(c.TargetID, "target_id")
		if err != nil {
			return nil, err
		}
		artifactID, err := parseOptionalUUID(c.ArtifactID, "artifact_id")
		if err != nil {
			return nil, err
		}
		out[i] = port.WaiverContext{
			EnvironmentID: envID,
			TargetID:      targetID,
			ArtifactID:    artifactID,
		}
	}
	return out, nil
}

// parseOptionalUUID validates an optional UUID field, returning an error
// labeled with the field name when the value is present but malformed.
func parseOptionalUUID(value, field string) (string, error) {
	if value == "" {
		return "", nil
	}
	id, err := uuid.Parse(value)
	if err != nil {
		return "", fmt.Errorf("invalid %s %q: %w", field, value, err)
	}
	return id.String(), nil
}

func (u *Usecases) DeleteWaiver(ctx context.Context, projectSlug, waiverID string) error {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectAdminForWaiver(ctx, project.ID); err != nil {
		return err
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return fmt.Errorf(errInvalidWaiverIDFormat, err)
	}

	if err := u.deps.Stores.Waivers.Delete(ctx, id.String(), project.ID); err != nil {
		return fmt.Errorf("delete waiver: %w", err)
	}
	return nil
}

func (u *Usecases) ToggleWaiver(ctx context.Context, projectSlug, waiverID, actorID string) (*WaiverResponse, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}
	if err := u.requireProjectAdminForWaiver(ctx, project.ID); err != nil {
		return nil, err
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return nil, fmt.Errorf(errInvalidWaiverIDFormat, err)
	}

	w, err := u.deps.Stores.Waivers.ToggleWithEvent(ctx, id.String(), project.ID, actorID)
	if err != nil {
		return nil, fmt.Errorf("toggle waiver: %w", err)
	}

	resp := toWaiver(w)
	return &resp, nil
}

func (u *Usecases) ListWaiverEvents(ctx context.Context, projectSlug, waiverID string) ([]WaiverEventResp, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return nil, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}

	id, err := uuid.Parse(waiverID)
	if err != nil {
		return nil, fmt.Errorf(errInvalidWaiverIDFormat, err)
	}

	if _, err := u.deps.Stores.Waivers.GetByID(ctx, id.String(), project.ID); err != nil {
		return nil, fmt.Errorf("get waiver: %w", err)
	}

	events, err := u.deps.Stores.Waivers.ListEvents(ctx, id.String())
	if err != nil {
		return nil, fmt.Errorf("list events: %w", err)
	}

	resp := make([]WaiverEventResp, len(events))
	for i, e := range events {
		resp[i] = toWaiverEvent(e)
	}
	return resp, nil
}

func (u *Usecases) CheckWaiverMatch(ctx context.Context, projectSlug, findingID string) (bool, error) {
	project, err := u.deps.Stores.Projects.GetBySlug(ctx, projectSlug)
	if err != nil {
		return false, fmt.Errorf(errLookupProjectFormat, projectSlug, err)
	}

	fid, err := uuid.Parse(findingID)
	if err != nil {
		return false, fmt.Errorf("invalid finding id: %w", err)
	}

	finding, err := u.deps.Stores.Findings.GetByID(ctx, fid.String())
	if err != nil {
		return false, fmt.Errorf("get finding: %w", err)
	}
	if finding.ProjectID != project.ID {
		return false, ErrProjectAccessDenied
	}
	if err := u.checkFindingProjectIDAccess(ctx, finding.ProjectID); err != nil {
		return false, err
	}

	gf := gate.Finding{
		ID:                  finding.ID,
		CurrentSeverityRank: finding.CurrentSeverityRank,
		FindingKind:         finding.FindingKind,
		Fingerprint:         finding.Fingerprint,
		CurrentTitle:        finding.CurrentTitle,
	}
	if fc, ctxErr := u.deps.Stores.Findings.GetFindingContext(ctx, fid.String()); ctxErr == nil {
		gf.EnvironmentID = fc.EnvironmentID
		gf.TargetID = fc.TargetID
		gf.ArtifactID = fc.ArtifactID
	}

	waivers, err := (&gateWaiverRepo{stores: u.deps.Stores}).ListActiveWaivers(ctx, project.ID)
	if err != nil {
		return false, fmt.Errorf("list active waivers: %w", err)
	}

	return gate.IsFindingWaived(gf, waivers), nil
}

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
